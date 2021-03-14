import logging
import os
import os.path
import re
import tempfile
import zipfile
import hashlib
from functools import cached_property, lru_cache

import r2pipe

from quark.android.axml import AxmlReader
from quark.common.bytecode import Bytecode
from quark.common.method import MethodId


class Apkinfo(object):
    """
    Information about apk based on radare2 analysis.
    """

    def __init__(self, apk_file, tmp_dir=None):
        """
        Load an apk and extract all the contains to a temporary dictionary.

        :param apk_file: path lead to an apk
        :type apk_file: str
        :param tmp_dir: a path where a temporary dictionary will generate, defaults to system temp
        :type tmp_dir: str, optional
        """
        self._filename = os.path.basename(apk_file)
        self._filepath = apk_file

        self._tmp_dir = tempfile.mkdtemp() if tmp_dir is None else tmp_dir

        # Extract file to tmp dir
        with zipfile.ZipFile(self._filepath) as apk:
            # Extract manifest
            apk.extract('AndroidManifest.xml', path=self._tmp_dir)
            # Extract all dex files
            self._dex_list = []
            for dex in filter(lambda f: f.startswith(
                    'classes') and f.endswith('.dex'), apk.namelist()):
                apk.extract(dex, path=self._tmp_dir)
                self._dex_list.append(os.path.join(self._tmp_dir, dex))

    @lru_cache()
    def _get_r2(self, index):
        r2 = r2pipe.open(self._dex_list[index])
        r2.cmd('aa')
        return r2

    def r2_escape(self, string: str) ->str:
        escapeList = ['>']

        result = ''
        for char in string:
            if char in escapeList:
                result = result + '\\'
            
            result = result + char

        return result

    @property
    def md5(self):
        md5 = hashlib.md5()
        with open(self.apk_filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @property
    def filename(self):
        return self._filename

    @property
    def filepath(self):
        return self._filepath

    @property
    def filesize(self):
        return os.path.getsize(self.filepath)

    @property
    def manifest(self):
        """
        Return a path to extracted manifest file.
        """
        return os.path.join(self._tmp_dir, 'AndroidManifest.xml')

    @property
    def dex_list(self):
        """
        Return a list of paths to extracted dex files
        """
        return self._dex_list

    @cached_property
    def permissions(self):
        """
        Return a set of app permissions which was defined in manifest file.s
        """
        axml = AxmlReader(self.manifest)
        permission_list = set()

        for tag in axml:
            if 'Name' in tag.keys() \
                    and axml.get_string(tag['Name']) == 'uses-permission':
                attrs = axml.get_attributes(tag)

                if not attrs is None:
                    permission = axml.get_string(attrs[0]['Value'])
                    permission_list.add(permission)

        return permission_list

    def find_methods_by_addr(self, dex_index, address):
        """
        Return a method object according to given address.

        :param address: a address
        :type address: number-like object
        :return: a method object or None
        :rtype: MethodId
        """
        if address < 0:
            return None

        r2 = self._get_r2(dex_index)
        section = r2.cmdj(f'iSj. @ {address}')
        if section is None or 'name' not in section or (section['name'] != 'constpool' and section['name'] != 'code'):
            return None

        symbol = r2.cmdj(f'isj. @ {address}')
        if symbol['type'] != 'FUNC':
            return None

        signature = symbol['realname']
        classname = signature[:signature.index('.method.')] + ';'
        methodname = signature[signature.index(
            '.method.') + 8:signature.index('(')]
        descriptor = signature[signature.index('('):]

        return MethodId(symbol['vaddr'], dex_index, classname, methodname, descriptor, symbol['is_imported'])

    def find_methods(self, classname='', methodname='', descriptor='', dex_index=None):
        """
        Find a list of methods matching given infomations.

        NOTE: finding method with only descriptor provided is not accurate currently.

        :param classname: Name of class which methods belong to , defaults to ''
        :type classname: str, optional
        :param methodname: Name of method for matching, defaults to ''
        :type methodname: str, optional
        :param descriptor: Descriptor of method for matching, defaults to ''
        :type descriptor: str, optional
        :param dex_index: Indicate where the given method is, defaults to None
        :type dex_index: non-negative number, optional
        :return: a list of methods
        :rtype: list of MethodId objects
        """
        method_filter = None
        if classname or methodname:
            if classname.endswith(';'):
                classname = classname[:-1]
            method_filter = f'&{classname}.method.{self.r2_escape(methodname)}'
            if methodname:
                method_filter += '('

        if descriptor:
            if method_filter is None:
                method_filter = f'{descriptor}'
            else:
                method_filter += f',{descriptor}'
        command = 'is~' + method_filter
        result = None

        if not dex_index:
            dex_index = -1
            for dex_index in range(len(self._dex_list)):
                r2 = self._get_r2(dex_index)
                result = r2.cmd(command)
                if result:
                    break
        else:
            r2 = self._get_r2(dex_index)
            result = r2.cmd(command)

        if not result:
            return []

        method_list = []
        for l in result.splitlines():
            segments = re.split(' +', l)
            if segments[4] != 'FUNC':
                continue

            # TODO - use isj for gathering infomations

            rs_address = int(segments[2], 16)

            signature = segments[-1]
            imported = signature.startswith('imp.')
            if imported:
                rs_classname = signature[4:signature.index('.method.')]
            else:
                rs_classname = signature[:signature.index('.method.')]
            rs_classname = rs_classname + ';'

            rs_methodname = signature[signature.index(
                '.method.') + 8:signature.index('(')]
            rs_descriptor = signature[signature.index('('):]

            method_list.append(
                MethodId(rs_address, dex_index, rs_classname, rs_methodname, rs_descriptor, imported))

        return method_list

    def find_upper_methods(self, method: MethodId):
        """
        Return the corresponding xref methods from given method. 

        :param method: a method object
        :type method: MethodId
        :yield: all xref methods
        :rtype: a generator of MethodId objects
        """

        r2 = self._get_r2(method.dexindex)

        xrefs = r2.cmdj(f'axtj @ {method.address}')

        for xref in xrefs:
            if xref['type'] != 'CALL':
                continue

            if 'from' in xref:
                yield (xref['from'], self.find_methods_by_addr(method.dexindex, xref['from']))
            else:
                logging.debug(f'Key from was not found at searching upper methods for {method}.')

    def get_function_bytecode(self, function: MethodId, start_offset=-1, end_offset=-1):
        """
        Return the corresponding bytecode according to the address of function in the given MethodId object.

        :param function: a MethodId object
        :type function: MethodId
        :yield: all bytecode instructions
        :rtype: a generator of bytecodeobject in quark-engine
        """

        if not function.is_import:

            r2 = self._get_r2(function.dexindex)

            instruct_flow = r2.cmdj(f'pdfj @ {function.address}')['ops']

            if instruct_flow:

                bytecode_obj = None
                for ins in instruct_flow:
                    if ins['offset'] < start_offset:
                        continue
                    if ins['offset'] >= end_offset:
                        break

                    yield Bytecode.get_by_smali(ins['offset'], ins['disasm'])

    def check_valid(self):
        pass

    def __del__(self):
        """
        Clean up all the extracted files.
        """
        try:
            for dirpath, _, files in os.walk(self._tmp_dir, False):
                for filename in files:
                    os.remove(os.path.join(dirpath, filename))
            os.rmdir(self._tmp_dir)
        except:
            pass

import os
import os.path
import re
import tempfile
import zipfile
import r2pipe
from functools import cached_property, lru_cache

from quark.Objects.bytecodeobject import BytecodeObject

from .axml import AxmlReader


class MethodId(object):
    """
    Information about a method in a dex file.
    """

    def __init__(self, address, dexindex, classname, methodname, descriptor, isAPI=False):
        self.address = address
        self.dexindex = dexindex
        self.classname = classname
        self.methodname = methodname
        self.descriptor = descriptor
        self.isAPI = isAPI

    def __eq__(self, obj):
        return isinstance(obj, MethodId) and obj.address == self.address and obj.classname == self.classname and obj.methodname == self.methodname and obj.descriptor == self.descriptor

    def __hash__(self):
        return hash(self.address) ^ hash(self.classname) ^ hash(self.methodname) ^ hash(self.descriptor)


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

    def find_methods(self, classname='', methodname='', descriptor=''):
        """
        Find a list of methods matching given infomations.

        NOTE: finding method with only descriptor provided is not accurate currently.

        :param classname: Name of class which methods belong to , defaults to ''
        :type classname: str, optional
        :param methodname: Name of method for matching, defaults to ''
        :type methodname: str, optional
        :param descriptor: Descriptor of method for matching, defaults to ''
        :type descriptor: str, optional
        :return: a list of methods
        :rtype: list of MethodId objects
        """
        method_filter = None
        if classname or methodname:
            method_filter = f'&{classname}.method.{methodname}'
            if methodname:
                method_filter += '('

        if descriptor:
            if method_filter is None:
                method_filter = f'{descriptor}'
            else:
                method_filter += f',{descriptor}'
        command = 'is~' + method_filter
        result = None

        # Use the first-matching result
        dexindex = -1
        for dexindex in range(len(self._dex_list)):
            r2 = self._get_r2(dexindex)
            result = r2.cmd(command)  # Method_id_items in dex file
            if result:
                break

        method_list = []
        for l in result.splitlines():
            segments = re.split(' +', l)
            rs_address = int(segments[2], 16)

            signature = segments[-1]
            imported = signature.startswith('imp.')
            if imported:
                rs_classname = signature[4:signature.index('.method.')]
            else:
                rs_classname = signature[:signature.index('.method.')]

            rs_methodname = signature[signature.index(
                '.method.')+8:signature.index('(')]
            rs_descriptor = signature[signature.index('('):]

            method_list.append(
                MethodId(rs_address, dexindex, rs_classname, rs_methodname, rs_descriptor, imported))

        return method_list

    def get_function_bytecode(self, function: MethodId):
        # TODO - add docstring

        if not function.isAPI:

            r2 = self._get_r2(function.dexindex)

            instruct_flow = r2.cmdj(f'pdfj @ {function.address}')['ops']

            if instruct_flow:

                bytecode_obj = None
                for ins in instruct_flow:
                    ins_part = re.split('[ {},]+', ins['disasm'])

                    # invoke-kind instruction may left method index at the last
                    if len(ins_part) >= 5 and ins_part[-2] == ';':
                        ins_part = ins_part[:-2]

                    # Parameters only appear at the last
                    if len(ins_part) >= 2 and not ins_part[-1].startswith('v'):
                        bytecode_obj = BytecodeObject(
                            ins_part[0], ins_part[1:-1], ins_part[-1])
                    else:
                        bytecode_obj = BytecodeObject(
                            ins_part[0], ins_part[1:], None)

                    yield bytecode_obj

    def check_valid(self):
        # TODO
        return True

    def __del__(self):
        """
        Clean up all the extracted files.
        """
        for dirpath, _, files in os.walk(self._tmp_dir, False):
            for filename in files:
                os.remove(os.path.join(dirpath, filename))
        os.rmdir(self._tmp_dir)

import os
import os.path
import tempfile
import zipfile
from functools import cached_property

from .axml import AxmlReader


class Apkinfo(object):
    """
    Information about apk based on radare2 analysis
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

    def find_method(self, class_name=".*", method_name=".*", descriptor=".*"):
        # TODO
        pass

    def check_valid(self):
        # TODO
        return True

    def __del__(self):
        """
        Clean up all the extracted files.
        """
        for dirpath, dirs, files in os.walk(self._tmp_dir, False):
            for filename in files:
                os.remove(os.path.join(dirpath, filename))
        os.rmdir(self._tmp_dir)

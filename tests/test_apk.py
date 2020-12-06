import hashlib
import os.path

import pytest
from android.apk import Apkinfo


@pytest.fixture(scope="class")
def apkinfo_obj():
    apk_file = 'tests/sample/HippoSMS.apk'
    return Apkinfo(apk_file)


def get_md5(file_path):
    with open(file_path, 'rb') as file:
        m = hashlib.md5()
        for chunk in iter(lambda: file.read(4096), b""):
            m.update(chunk)
    return m.hexdigest()


class TestApkinfo(object):

    def test_manifest(self, apkinfo_obj):
        md5 = get_md5(apkinfo_obj.manifest)
        assert md5 == 'af294c67c4d37c27a84b69dbc930efd4'

    def test_dex_list(self, apkinfo_obj):
        # TODO - Find a sample with multi-dex
        truth = {
            'classes.dex': 'ca8bcc8db3963fd1935b21009bcaa717'
        }

        for dex in apkinfo_obj.dex_list:
            file_name = os.path.basename(dex)
            assert file_name in truth.keys()
            md5 = get_md5(dex)
            assert md5 == truth[file_name]

    def test_permissions(self, apkinfo_obj):
        assert apkinfo_obj.permissions == set([
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
            'android.permission.SEND_SMS',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.RECEIVE_BOOT_COMPLETED',
            'android.permission.RECEIVE_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.READ_SMS',
            'com.android.launcher.permission.INSTALL_SHORTCUT'
        ])

    def test_delete(self, apkinfo_obj):
        tmp = apkinfo_obj._tmp_dir
        apkinfo_obj.__del__()
        assert not os.path.exists(tmp)

import pytest
import zipfile
import os

from android.apk import get_permissions


<<<<<<< HEAD
<<<<<<< HEAD
=======
@pytest.fixture(scope="module")
def manifest_file():
    return 'tests/sample/HippoSMS/AndroidManifest.axml'
>>>>>>> 05618c1 (Test for get_permissions())
=======
@pytest.fixture(scope="module")
def dex_file():
    return 'tests/sample/HippoSMS/classes.dex'
>>>>>>> 0713a65 (Temp)


def test_get_permissions(manifest_file):
    assert get_permissions(manifest_file) == set([
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

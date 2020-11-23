import tempfile
import zipfile
import os

from android.apk import get_permissions

_temp = None


def setup_module():
    global _temp
    _temp = tempfile.TemporaryDirectory()

    with zipfile.ZipFile('tests/sample/HippoSMS.apk') as zip:
        zip.extract('classes.dex', path=_temp.name)
        zip.extract('AndroidManifest.xml', path=_temp.name)


def test_get_permissions():
    manifest_path = os.path.join(_temp.name, 'AndroidManifest.xml')

    assert get_permissions(manifest_path) == set([
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

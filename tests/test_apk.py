import hashlib
import os.path

import pytest
from android.apk import Apkinfo, MethodId

from quark.Objects.bytecodeobject import BytecodeObject


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


class TestMethodId(object):

    def test_eq(self):
        truth = MethodId(0x0A, -1, 'Ljava/lang/Object',
                         'toString', '()Ljava/lang/String;')

        assert MethodId(0x0A, -1, 'Ljava/lang/Object', 'toString',
                        '()Ljava/lang/String;') == truth

        assert MethodId(0x0B, -1, 'Ljava/lang/Object', 'toString',
                        '()Ljava/lang/String;') != truth
        assert MethodId(0x0A, -1, 'Ljava/lang/String', 'toString',
                        '()Ljava/lang/String;') != truth
        assert MethodId(0x0A, -1, 'Ljava/lang/Object', 'asString',
                        '()Ljava/lang/String;') != truth
        assert MethodId(0x0A, -1, 'Ljava/lang/Object', 'toString',
                        '()Ljava/lang/Object;') != truth

    def test_hash(self):
        assert hash(MethodId(0x0A, -1, 'Ljava/lang/Object', 'toString', '()Ljava/lang/String;')
                    ) == hash(MethodId(0x0A, -1, 'Ljava/lang/Object', 'toString', '()Ljava/lang/String;'))


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

    def test_find_methods(self, apkinfo_obj):
        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList', methodname='add', descriptor='(Ljava/lang/Object;)Z')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList', 'add', '(Ljava/lang/Object;)Z'),))

        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList', methodname='add')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList', 'add', '(Ljava/lang/Object;)Z'),))

        result = apkinfo_obj.find_methods(
            methodname='setNegativeButton', descriptor='(ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;')
        assert set(result) == set((MethodId(0x48B0, -1, 'Landroid/app/AlertDialog$Builder', 'setNegativeButton',
                                            '(ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;'),))

        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList', descriptor='(Ljava/lang/Object;)Z')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList', 'add', '(Ljava/lang/Object;)Z'),))

        result = apkinfo_obj.find_methods(classname='Ljava/util/ArrayList')
        assert set(result) == set((MethodId(0x6DA8, -1, 'Ljava/util/ArrayList', '<init>', '()V'),
                                   MethodId(0x6DB0, -1, 'Ljava/util/ArrayList',
                                            'add', '(Ljava/lang/Object;)Z'),
                                   MethodId(0x6DB8, -1, 'Ljava/util/ArrayList',
                                            'addAll', '(Ljava/util/Collection;)Z'),
                                   MethodId(
            0x6DC0, -1, 'Ljava/util/ArrayList', 'clear', '()V'),
            MethodId(0x6DC8, -1, 'Ljava/util/ArrayList',
                     'get', '(I)Ljava/lang/Object;'),
            MethodId(0x6DD0, -1, 'Ljava/util/ArrayList',
                     'remove', '(I)Ljava/lang/Object;'),
            MethodId(0x6DD8, -1, 'Ljava/util/ArrayList', 'size', '()I')))

        result = apkinfo_obj.find_methods(methodname='add')
        assert set(result) == set((
            MethodId(0x4C40, -1, 'Landroid/view/Menu', 'add',
                     '(IIILjava/lang/CharSequence;)Landroid/view/MenuItem;'),
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList',
                     'add', '(Ljava/lang/Object;)Z'),
            MethodId(0x6E20, -1, 'Ljava/util/List',
                     'add', '(Ljava/lang/Object;)Z'),
            MethodId(0x6E70, -1, 'Ljava/util/Vector',
                     'add', '(Ljava/lang/Object;)Z')
        ))

        # result = func(descriptor='(Ljava/lang/Object;)Z')
        # TODO - r2 give a unreasonable output, need to check again.

    def test_find_upper_functions(self, apkinfo_obj):
        method = MethodId(0x883C, 0, 'La', 'LaLa', 'Land', False)

        assert set(apkinfo_obj.find_upper_methods(method)) == {
            MethodId(0x9388, 0, 'Lcom/ku6/android/videobrowser/About_Activity',
                     'onCreate', '(Landroid/os/Bundle;)V')
        }

        method = MethodId(0xE758, 0, 'La', 'LaLa', 'Land', False)

        assert set(apkinfo_obj.find_upper_methods(method)) == {
            MethodId(0xDDCC, 0, 'Lcom/ku6/android/videobrowser/Search_Activity$4',
                     'onItemClick', '(Landroid/widget/AdapterView;Landroid/view/View;IJ)V', False),
            MethodId(0xE7C0, 0, 'Lcom/ku6/android/videobrowser/Search_Activity',
                     'setSearchKeyword', '(Ljava/lang/String;)V', False)
        }

    def test_get_function_bytecode(self, apkinfo_obj):
        # API functions
        bytecode_list = apkinfo_obj.get_function_bytecode(
            MethodId(0xF, 0, 'LaLa', 'La', 'Land', True))
        for _ in bytecode_list:
            assert False

        # Non-API functions
        bytecode_list = apkinfo_obj.get_function_bytecode(
            MethodId(0x8ABC, 0, 'LaLa', 'La', 'Land', False))
        assert [bytecode for bytecode in bytecode_list] == [
            BytecodeObject('new-instance', ['v0'],
                           'Landroid/app/ProgressDialog;'),
            BytecodeObject(
                'invoke-direct', ['v0', 'v2'], 'Landroid/app/ProgressDialog.<init>(Landroid/content/Context;)V'),
            BytecodeObject(
                'invoke-virtual', ['v0', 'v3'], 'Landroid/app/ProgressDialog.setTitle(Ljava/lang/CharSequence;)V'),
            BytecodeObject(
                'invoke-virtual', ['v0', 'v4'], 'Landroid/app/ProgressDialog.setMessage(Ljava/lang/CharSequence;)V'),
            BytecodeObject('return-object', ['v0'], None),
        ]

        bytecode_list = apkinfo_obj.get_function_bytecode(
            MethodId(0x994C, 0, 'LaLa', 'La', 'Land')
        )
        assert [bytecode for bytecode in bytecode_list] == [
            BytecodeObject('iget-object', ['v0','v1'], 'Lcom/ku6/android/videobrowser/ChannelDetailAdapter;->coll Ljava/util/ArrayList;'),
            BytecodeObject('invoke-virtual', ['v0','v2'], 'Ljava/util/ArrayList.get(I)Ljava/lang/Object;'),
            BytecodeObject('move-result-object', ['v0'], None),
            BytecodeObject('return-object', ['v0'], None)
        ]

    def test_delete(self, apkinfo_obj):
        tmp = apkinfo_obj._tmp_dir
        apkinfo_obj.__del__()
        assert not os.path.exists(tmp)

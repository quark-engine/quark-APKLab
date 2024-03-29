import hashlib
import os.path

import pytest
from quark.android.apk import Apkinfo, MethodId, Bytecode


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
        truth = MethodId(0x0A, -1, 'Ljava/lang/Object;',
                         'toString', '()Ljava/lang/String;')

        assert MethodId(0x0A, -1, 'Ljava/lang/Object;', 'toString',
                        '()Ljava/lang/String;') == truth

        assert MethodId(0x0A, -1, 'Ljava/lang/String;', 'toString',
                        '()Ljava/lang/String;') != truth
        assert MethodId(0x0A, -1, 'Ljava/lang/Object;', 'asString',
                        '()Ljava/lang/String;') != truth
        assert MethodId(0x0A, -1, 'Ljava/lang/Object;', 'toString',
                        '()Ljava/lang/Object;') != truth

    def test_hash(self):
        assert hash(MethodId(0x0A, -1, 'Ljava/lang/Object;', 'toString', '()Ljava/lang/String;')
                    ) == hash(MethodId(0x0A, -1, 'Ljava/lang/Object;', 'toString', '()Ljava/lang/String;'))


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

    def test_find_method_by_addr(self, apkinfo_obj):
        # Illegal addresses
        assert apkinfo_obj.find_methods_by_addr(0, -1) == None
        assert apkinfo_obj.find_methods_by_addr(0, 0) == None
        assert apkinfo_obj.find_methods_by_addr(0, 0xFFFFFFFF) == None

        # API functions
        assert apkinfo_obj.find_methods_by_addr(0, 0x6DB0) == MethodId(0x6D98, 0, 'Ljava/text/SimpleDateFormat;',
                                                                       '<init>', '(Ljava/lang/String;)V')
        # Non-API functions
        assert apkinfo_obj.find_methods_by_addr(0, 0xE758) == MethodId(
            0xE758, 0, 'Lcom/ku6/android/videobrowser/Search_Activity;', 'search', '(Ljava/lang/String;)V')

    def test_get_all_methods_structured(self, apkinfo_obj):
        truths = [
            MethodId(0x883C, 0, 'Lcom/ku6/android/videobrowser/About_Activity$1;',
                     '<init>', '(Lcom/ku6/android/videobrowser/About_Activity;)V'),
            MethodId(0x8858, 0, 'Lcom/ku6/android/videobrowser/About_Activity$1;',
                     'onClick', '(Landroid/view/View;)V'),
            MethodId(
                0x88AC, 0, 'Lcom/ku6/android/videobrowser/Base_Activity;', '<init>', '()V'),
            MethodId(0x88C4, 0, 'Lcom/ku6/android/videobrowser/Base_Activity;',
                     'buildDialog3', '(Landroid/content/Context;)Landroid/app/Dialog;'),
            MethodId(0x8928, 0, 'Lcom/ku6/android/videobrowser/Base_Activity;',
                     'buildDialog5', '(Landroid/content/Context;)Landroid/app/Dialog;')
        ]

        for truth in truths:
            assert truth in apkinfo_obj.get_all_methods_classified(0)[truth.classname]

    def test_find_methods(self, apkinfo_obj):
        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList;', methodname='add', descriptor='(Ljava/lang/Object;)Z')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList;', 'add', '(Ljava/lang/Object;)Z'),))

        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList;', methodname='add')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList;', 'add', '(Ljava/lang/Object;)Z', True),))

        result = apkinfo_obj.find_methods(
            classname='Ljava/util/ArrayList;', descriptor='(Ljava/lang/Object;)Z')
        assert set(result) == set((
            MethodId(0x6DB0, -1, 'Ljava/util/ArrayList;', 'add', '(Ljava/lang/Object;)Z'),))

        result = apkinfo_obj.find_methods(classname='Ljava/util/ArrayList;')
        assert set(result) == set((MethodId(0x6DA8, -1, 'Ljava/util/ArrayList;', '<init>', '()V'),
                                   MethodId(0x6DB0, -1, 'Ljava/util/ArrayList;',
                                            'add', '(Ljava/lang/Object;)Z'),
                                   MethodId(0x6DB8, -1, 'Ljava/util/ArrayList;',
                                            'addAll', '(Ljava/util/Collection;)Z'),
                                   MethodId(
            0x6DC0, -1, 'Ljava/util/ArrayList;', 'clear', '()V'),
            MethodId(0x6DC8, -1, 'Ljava/util/ArrayList;',
                     'get', '(I)Ljava/lang/Object;'),
            MethodId(0x6DD0, -1, 'Ljava/util/ArrayList;',
                     'remove', '(I)Ljava/lang/Object;'),
            MethodId(0x6DD8, -1, 'Ljava/util/ArrayList;', 'size', '()I')))
            
        # result = func(descriptor='(Ljava/lang/Object;)Z')
        # TODO - r2 give a unreasonable output, need to check again.

    def test_find_upper_functions(self, apkinfo_obj):
        # API functions
        method = MethodId(0x6C98, 0, 'Ljava/lang/String;',
                          'length', '()I', True)

        assert set(apkinfo_obj.find_upper_methods(method)) == {
            (59340, MethodId(0xE7C0, 0, 'Lcom/ku6/android/videobrowser/Search_Activity;',
                             'setSearchKeyword', '(Ljava/lang/String;)V')),
            (61626, MethodId(0xF0B0, 0, 'Lcom/ku6/android/videobrowser/Search_Result_Activity;',
                             'setSearchKeyword', '(Ljava/lang/String;)V')),
            (68208, MethodId(0x10A48, 0, 'Lcom/ku6/android/videobrowser/SplashActivity;',
                             'getDataSource', '(Lcom/ku6/android/videobrowser/entity/Version;)V')),
        }

        # Non-API functions
        method = MethodId(
            0xE758, 0, 'Lcom/ku6/android/videobrowser/Search_Activity', 'search', '(Ljava/lang/String;)V')

        assert set(apkinfo_obj.find_upper_methods(method)) == {
            (56826, MethodId(0xDDCC, 0, 'Lcom/ku6/android/videobrowser/Search_Activity$4;',
                             'onItemClick', '(Landroid/widget/AdapterView;Landroid/view/View;IJ)V', False)),
            (59372, MethodId(0xE7C0, 0, 'Lcom/ku6/android/videobrowser/Search_Activity;',
                             'setSearchKeyword', '(Ljava/lang/String;)V', False))
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
            Bytecode(0x8ABC, 'new-instance', [0],
                     'Landroid/app/ProgressDialog;'),
            Bytecode(0x8AC0,
                     'invoke-direct', [0, 2], 'Landroid/app/ProgressDialog.<init>(Landroid/content/Context;)V'),
            Bytecode(0x8AC6,
                     'invoke-virtual', [0, 3], 'Landroid/app/ProgressDialog.setTitle(Ljava/lang/CharSequence;)V'),
            Bytecode(0x8ACC,
                     'invoke-virtual', [0, 4], 'Landroid/app/ProgressDialog.setMessage(Ljava/lang/CharSequence;)V'),
            Bytecode(0x8AD2, 'return-object', [0]),
        ]

        bytecode_list = apkinfo_obj.get_function_bytecode(
            MethodId(0x994C, 0, 'LaLa', 'La', 'Land')
        )
        assert [bytecode for bytecode in bytecode_list] == [
            Bytecode(0x994C,
                     'iget-object', [0, 1], 'Lcom/ku6/android/videobrowser/ChannelDetailAdapter;->coll Ljava/util/ArrayList;'),
            Bytecode(0x9950,
                     'invoke-virtual', [0, 2], 'Ljava/util/ArrayList.get(I)Ljava/lang/Object;'),
            Bytecode(0x9956, 'move-result-object', [0]),
            Bytecode(0x9958, 'return-object', [0])
        ]

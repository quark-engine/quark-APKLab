
import os.path
import click
import treelib

from android.axml import AxmlReader, RES_XML_START_ELEMENT_TYPE, RES_XML_END_ELEMENT_TYPE
from android.apk import Apkinfo

def display_axml(file_path):
    axml_reader = AxmlReader(file_path)

    counter = 0
    parent = None
    tree = treelib.Tree()

    for tag in axml_reader:
        if tag['Type']==RES_XML_START_ELEMENT_TYPE:
            parent = tree.create_node(counter, tag['Name'], parent=parent)
            counter = counter + 1

        elif tag['Type']==RES_XML_END_ELEMENT_TYPE:
            # TODO - Get parent's parent, and the set to parent
            pass

    print(f'Total nodes scanned: {counter}')
    tree.show()

def display_apk_info(file_path, permission: bool, list_methods: bool, show_bytecode: bool, *targets):
    apkinfo = Apkinfo(file_path)

    print(f'Name: {apkinfo.filename}')
    print(f'Path: {apkinfo.filepath}')
    print('dex_list:')
    for dex in apkinfo.dex_list:
        print(f'- {os.path.basename(dex)}')

    print()

    if permission:
        print('Permissions:')
        for permission in apkinfo.permissions:
            print(f'- {permission}')

    if list_methods:
        print('Methods: ')
        method_list = list(apkinfo.find_methods())
        for i in range(len(method_list)):
            print(f'- {i:>2} {method_list[i]}')
            
    if show_bytecode:
        index = int(input('Index of a method to found -> '))

        if not method_list:
            method_list = apkinfo.find_methods()

        method = method_list[index]
        print(f'Method: {method}')
        print(f'isAPI : {method.isAPI}')
        bytecodes = list(apkinfo.get_function_bytecode(method))

        for i in len(bytecodes):
            print(f' - {i:>2} {bytecodes[i]}')
        print()

@click.command
@click.option('-f', '--file-path', type=click.Path(exists=True,file_okay=True, dir_okay=False,readable=True))
@click.option('--axml', flag_command='mode', value='axml')
@click.option('--apk' , flag_command='mode', value='apk' )
@click.option('-p', '--show-permissions', type=bool, default=False)
@click.option('-l', '--list-methods', type=bool, default=False)
@click.option('-s', '--show-bytecode', type=bool, default=False)
@click.option('-t', '--target', type=str)

def main(mode, file_path, permission, list_methods, show_bytecode, targets):
    
    if mode == 'axml':
        display_axml(file_path)
    elif mode == 'apk':
        display_apk_info(file_path, permission, list_methods, show_bytecode, targets)

if __name__ == "__main__":
    main()
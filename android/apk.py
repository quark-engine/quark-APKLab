import tempfile
import zipfile

from .axml import AxmlReader


def get_permissions(manifest_file):
    axml = AxmlReader(manifest_file)
    permission_list = set()

    for tag in axml:
        if 'Name' in tag.keys() \
                and axml.get_string(tag['Name']) == 'uses-permission':
            attrs = axml.get_attributes(tag)

            if not attrs is None:
                permission = axml.get_string(attrs[0]['Value'])
                permission_list.add(permission)

    return permission_list


def check_valid(file_path):
    # TODO
    return True

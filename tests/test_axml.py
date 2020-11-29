import pytest
import treelib
import xml.etree.ElementTree as et
from android.axml import AxmlReader, AxmlException, Res_value_type, RES_XML_START_ELEMENT_TYPE, RES_XML_END_ELEMENT_TYPE


@pytest.fixture(scope='module')
def axml_file():
    return 'tests/sample/HippoSMS/AndroidManifest.axml'


@pytest.fixture(scope='module')
def xml_file():
    return 'tests/sample/HippoSMS/AndroidManifest.xml'


def test_axml_info(axml_file: str):
    axml = AxmlReader(axml_file)
    assert axml.file_size == 5756
    assert axml.axml_size == 5756
    assert axml._stringCount == 56


def test_get_string(axml_file: str):
    axml = AxmlReader(axml_file)
    assert axml.get_string(0) == 'versionCode'


def test_get_attributes(axml_file: str):
    axml = AxmlReader(axml_file)

    iterator = iter(axml)
    node = None
    while True:
        node = next(iterator)
        if node['Type'] == RES_XML_START_ELEMENT_TYPE:
            break

    attributes = axml.get_attributes(node)

    truths = [
        {'Namespace': 11,
         'Name': 0,
         'Value': -1,
         'Type': 16,
         'Data': 20},
        {'Namespace': 11,
         'Name': 1,
         'Value': 16,
         'Type': 3,
         'Data': 16},
        {'Namespace': -1,
         'Name': 13,
         'Value': 15,
         'Type': 3,
         'Data': 15}
    ]

    assert len(attributes) == len(truths)
    for i in range(3):
        for key in attributes[i].keys():
            assert attributes[i][key] == truths[i][key]


def test_xml(xml_file):
    with pytest.raises(AxmlException):
        AxmlReader(xml_file)


def test_axml(axml_file: str, xml_file: str):
    axml = AxmlReader(axml_file)
    xml = et.ElementTree(file=xml_file)

    def comb_ns_name(element: dict):
        name = element['Name']
        ns = element['Namespace']
        return axml.get_string(name) if ns == -1 else f'{{{axml.get_string(ns)}}}{axml.get_string(name)}'

    reply_it = iter(axml)
    while True:
        reply = next(reply_it)
        if reply['Type'] == RES_XML_START_ELEMENT_TYPE:
            break

    attributes = axml.get_attributes(reply)

    truth = xml.getroot()
    assert len(truth.attrib) == len(attributes)

    truth_attrs = truth.attrib
    for attr in attributes:
        key = comb_ns_name(attr)
        assert key in truth_attrs.keys()
        if attr['Value'] == -1:
            assert truth_attrs[key] == str(attr['Data'])
        else:
            assert truth_attrs[key] == axml.get_string(attr['Data'])

    stack = [truth]
    while len(stack) != 0:
        reply = next(reply_it)
        reply_name = comb_ns_name(reply)

        if reply['Type'] == RES_XML_START_ELEMENT_TYPE:
            truth_parent = stack[-1]
            reply_attrs = axml.get_attributes(reply)

            found = None
            for truth in truth_parent:
                if reply_name == truth.tag:
                    truth_attrs = truth.attrib
                    for attr in reply_attrs:
                        key = comb_ns_name(attr)
                        if not (key in truth_attrs.keys() and ((attr['Value'] == -1) or truth_attrs[key] == axml.get_string(attr['Value']))):
                            break
                    else:
                        found = truth
                        break

            if found is None:
                assert False, f'Reply {comb_ns_name(reply)}({reply}) was not match list {[truth.tag for truth in truth_parent]} which parent is {truth_parent.tag}'

            stack.append(truth)

        elif reply['Type'] == RES_XML_END_ELEMENT_TYPE:
            truth = stack.pop()

            assert reply_name == truth.tag

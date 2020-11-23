import json
import os.path
import r2pipe

# Resource Types Definition
# reference to https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/include/androidfw/ResourceTypes.h

# ResChunk_header types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

# Chunk types in RES_XML_TYPE
RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_LAST_CHUNK_TYPE = 0x017f
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203
RES_TABLE_OVERLAYABLE_TYPE = 0x0204
RES_TABLE_OVERLAYABLE_POLICY_TYPE = 0x0205


class AxmlException(Exception):
    """
    :message 
    """

    def __init__(self, message):
        """
        docstring
        """
        super(AxmlException, self).__init__(message)


class AxmlReader(object):
    """
    docstring
    """

    def __init__(self, file_path, struct_path=None):
        if struct_path is None:
            directory = 'android/struct'
            struct_path = os.path.join(directory, 'axml')

        if not os.path.isfile(struct_path):
            raise AxmlException('找不到 Radare2 結構定義檔')

        self._r2 = r2pipe.open(file_path)
        self._r2.cmd(f'pfo {struct_path}')

        self._file_size = int(self._r2.cmd('i~size[1]'), 16)
        self._ptr = 0

        self._cache = {}

        if self._file_size > 0xFFFF_FFFF:
            raise AxmlException("開啟檔案超過理論上限，是否確定檔案為 AXML")
        elif self._file_size < 8:
            raise AxmlException("開啟檔案小於理論下限，是否確定檔案為 AXML")

        # File Header
        header = self._r2.cmdj('pfj axml_ResChunk_header @ 0x0')

        self._data_type = header[0]['value']
        self._axml_size = header[2]['value']
        header_size = header[1]['value']

        if self._data_type != RES_XML_TYPE or header_size != 0x8:
            raise AxmlException("開啟檔案格式錯誤，是否確定檔案為 XML ?")

        if (self._axml_size > self._file_size):
            raise AxmlException(
                f'預期檔案容量({self._axml_size})大於實際容量({self._file_size})')

        if (self._axml_size < self._file_size):
            print_warning(
                f'預期檔案容量({self._axml_size})小於實際容量({self._file_size})，檔案可能被附加資料')

        self._ptr = self._ptr+8
        if self._ptr >= self._axml_size:
            return

        # String Pool
        string_pool_header = self._r2.cmdj('pfj axml_ResStringPool_header @ 8')

        string_pool_size = string_pool_header[0]['value'][2]['value']

        if string_pool_size > self._axml_size - self._ptr:
            raise AxmlException(f'資料長度不足，應至少有 {total_size} 但只有 {size}')

        header = string_pool_header[0]['value']
        header_type = header[0]['value']
        header_size = header[1]['value']

        if header_type != RES_STRING_POOL_TYPE:
            raise AxmlException(f'檔案格式錯誤，預期於 {self._ptr} 讀到字串池')

        if header_size != 28:
            raise AxmlException(f'檔案格式錯誤，字串池大小應是 28 而不是 { header_size }')

        self._stringCount = string_pool_header[0]["value"][1]["value"]
        stringStart = string_pool_header[4]["value"]

        self._r2.cmd(f'f string_pool_header @ 0x8 ')
        string_pool_index = self._stringCount + self._ptr
        self._r2.cmd(f'f string_pool_index @ { string_pool_index }')
        string_pool_data = stringStart + self._ptr
        self._r2.cmd(f'f string_pool_data @ { string_pool_data }')

        self._ptr = self._ptr + string_pool_size
        if self._ptr >= self._axml_size:
            return

        # Resource Map (Optional)
        header = self._r2.cmdj(f'pfj axml_ResChunk_header @ {self._ptr}')

        header_type = header[0]['value']
        map_size = header[2]['value']

        if header_type == RES_XML_RESOURCE_MAP_TYPE:
            # Skip all the resource map

            if map_size > self._axml_size - self._ptr:
                raise AxmlException(f'資料長度不足，應至少有 {total_size} 但只有 {size}')
                return

            self._ptr = self._ptr + map_size
            if self._ptr >= self._axml_size:
                return

    def __iter__(self):
        # Composed of a series of ResXMLTree_node and node extends

        while (self._axml_size - self._ptr >= 16):
            header = self._r2.cmdj(f'pfj axml_ResXMLTree_node @ {self._ptr}')

            node_type = header[0]['value'][0]['value']
            header_size = header[0]['value'][1]['value']
            node_size = header[0]['value'][2]['value']

            if header_size != 16:
                raise AxmlException(
                    f'標頭大小與預期不符，讀到 {header_size} 而不是 16，或許是 Bug?')

            if node_size > self._axml_size - self._ptr:
                raise AxmlException(
                    f'資料長度不足，應至少有 {node_size} 但只有 {self._axml_size - self._ptr}')

            ext_ptr = self._ptr + 16

            node = {
                'Address': self._ptr,
                'Type': node_type
            }

            if node_type == RES_XML_START_ELEMENT_TYPE:
                ext = self._r2.cmdj(
                    f'pfj axml_ResXMLTree_attrExt @ { ext_ptr }')

                node['Namespace'] = ext[0]['value'][0]['value']
                node['Name'] = ext[1]['value'][0]['value']

                # Attributes
                # node['AttrCount'] = ext[4]['value']

            elif node_type == RES_XML_END_ELEMENT_TYPE:
                ext = self._r2.cmdj(
                    f'pfj axml_ResXMLTree_endElementExt @ { ext_ptr }')

                node['Namespace'] = ext[0]['value'][0]['value']
                node['Name'] = ext[1]['value'][0]['value']

            elif node_type == RES_XML_START_NAMESPACE_TYPE or node_type == RES_XML_END_NAMESPACE_TYPE:
                ext = self._r2.cmdj(
                    f'pfj axml_ResXMLTree_namespaceExt @ { ext_ptr }')

                node['Prefix'] = ext[0]['value'][0]['value']
                node['Uri'] = ext[1]['value'][0]['value']

            elif node_type == RES_XML_CDATA_TYPE:
                ext = self._r2.cmdj(
                    f'pfj axml_ResXMLTree_cdataExt @ { ext_ptr }')

                node['Data'] = ext[0]['value'][0]['value']
                # typedData

            else:
                #print_warning(f'未知的資料，嘗試跳過 {node_type} bytes')
                self._ptr = self._ptr + node_size
                continue

            self._ptr = self._ptr + node_size
            yield node

        if self._ptr != self._file_size:
            print_warning(f'{ self._file_size - self._ptr } byte 遺留於檔案之後')

    @property
    def file_size(self):
        return self._file_size

    @property
    def axml_size(self):
        return self._axml_size

    def get_string(self, index) -> str:
        if index < 0:
            return None

        if not index in self._cache.keys():
            self._cache[index] = self._r2.cmdj(
                f'pfj Z @ string_pool_data + `pfv n4 @ string_pool_index+ {index}*4` + 2')[0]['string']

        return self._cache[index]

    def get_attributes(self, node) -> list:
        if node['Type'] != RES_XML_START_ELEMENT_TYPE:
            return None
        extAddress = int(node['Address']) + 16

        attrExt = self._r2.cmdj(f'pfj axml_ResXMLTree_attrExt @ {extAddress}')

        attrAddress = extAddress + attrExt[2]['value']
        attributeSize = attrExt[3]['value']
        attributeCount = attrExt[4]['value']
        result = []
        for _ in range(attributeCount):
            attr = self._r2.cmdj(
                f'pfj axml_ResXMLTree_attribute @ {attrAddress}')

            result.append({
                "Namespace": attr[0]['value'][0]['value'],
                "Name": attr[1]['value'][0]['value'],
                "Value": attr[2]['value'][0]['value'],
                "Type": attr[3]['value'][2]['value'],
                "Data": attr[3]['value'][3]['value']
            })

            attrAddress = attrAddress + attributeSize

        return result

    def __del__(self):
        self._r2.quit()

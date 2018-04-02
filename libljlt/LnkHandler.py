import io
import os
import re
import json
import pylnk
import pyfwsi
import struct
import pyolecf
import logging
from collections import OrderedDict
from libljlt.JsonDecoder import ComplexEncoder
from libljlt import Helpers


def format_serial(serial_int):
    """Format the volume serial number as a string.

    Args:
        serial_int (long|int): The integer representing the volume serial number
    Returns:
        (str): The string representation xxxx-xxxx
    """
    serial_str = None

    if serial_int == 0:
        return serial_str

    if serial_int is not None:
        serial_str = hex(serial_int)[2:-1].zfill(8)
        serial_str = serial_str[:4] + '-' + serial_str[4:]

    return serial_str


def get_shell_type(libfwsi_item):
    """Get a shell abstract type.

    Args:
        libfwsi_item (libfwsi.item): The shell item
    Returns:
        TypeVolume|TypeRootFolder|TypeFileEntryExtension|TypeFileEntry|TypeNetworkLocation
    """
    class_str = type(libfwsi_item).__name__
    class_int = libfwsi_item.get_class_type()

    shell_class = None
    if class_str == 'volume':
        shell_class = TypeVolume(libfwsi_item)
    elif class_str == 'root_folder':
        shell_class = TypeRootFolder(libfwsi_item)
    elif class_str == 'file_entry_extension':
        shell_class = TypeFileEntryExtension(libfwsi_item)
    elif class_str == 'file_entry':
        shell_class = TypeFileEntry(libfwsi_item)
    elif class_str == 'network_location':
        shell_class = TypeNetworkLocation(libfwsi_item)
    else:
        logging.debug("unhandled shell item class type: {}, {}".format(class_str,class_int))
    return shell_class


class Uuid(object):
    def __init__(self, raw_buffer):
        self._bytes = raw_buffer

    def __str__(self):
        return "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
            struct.unpack("<L", self._bytes[0:4])[0],
            struct.unpack("<H", self._bytes[4:6])[0],
            struct.unpack("<H", self._bytes[6:8])[0],
            struct.unpack("<B", self._bytes[8:9])[0],
            struct.unpack("<B", self._bytes[9:10])[0],
            struct.unpack("<B", self._bytes[10:11])[0],
            struct.unpack("<B", self._bytes[11:12])[0],
            struct.unpack("<B", self._bytes[12:13])[0],
            struct.unpack("<B", self._bytes[13:14])[0],
            struct.unpack("<B", self._bytes[14:15])[0],
            struct.unpack("<B", self._bytes[15:16])[0]
        )


class DestList(object):
    def __init__(self, raw_buffer):
        self.header = DestListHeader(
            raw_buffer[:32]
        )
        self.entries = []

        offset = 32
        for i in range(self.header.entry_count):
            if self.header.version == 1:
                entry = DestListEntryV1(
                    raw_buffer[offset:]
                )
                self.entries.append(entry)
                offset += 114 + entry.path_size
            elif self.header.version == 3:
                entry = DestListEntryV3(
                    raw_buffer[offset:]
                )
                self.entries.append(entry)
                offset += 130 + entry.path_size + 4
            elif self.header.version == 4:
                entry = DestListEntryV4(
                    raw_buffer[offset:]
                )
                self.entries.append(entry)
                offset += 130 + entry.path_size + 4
            else:
                raise(
                    Exception(
                        u'Unhandled DestList entry with header version: {}; RAW BUFFER: {}'.format(
                            self.header.version,
                            raw_buffer.hex()
                        )
                    )
                )

    def __iter__(self):
        for entry in self.entries:
            yield entry


class DestListHeader(object):
    def __init__(self, raw_buffer):
        self.version = struct.unpack("<L", raw_buffer[0:4])[0]
        self.entry_count = struct.unpack("<L", raw_buffer[4:8])[0]
        self.pinned_entry_count = struct.unpack("<L", raw_buffer[8:12])[0]
        self.unknown_1 = struct.unpack("<L", raw_buffer[12:16])[0]
        self.unknown_2 = struct.unpack("<L", raw_buffer[16:20])[0]
        self.unknown_3 = struct.unpack("<L", raw_buffer[20:24])[0]
        self.unknown_4 = struct.unpack("<L", raw_buffer[24:28])[0]
        self.unknown_5 = struct.unpack("<L", raw_buffer[28:32])[0]

    def as_dict(self):
        record = OrderedDict([
            ("version", self.version),
            ("entry_count", self.entry_count),
            ("pinned_entry_count", self.pinned_entry_count),
        ])
        return record


class DestListEntryV1(object):
    def __init__(self, raw_buffer):
        self.unknown1 = raw_buffer[0:8].hex()
        self.droid_volume_identifier = Uuid(raw_buffer[8:8+16])
        self.droid_file_identifier = Uuid(raw_buffer[24:24+16])
        self.birth_droid_volume_identifier = Uuid(raw_buffer[40:40+16])
        self.birth_droid_file_identifier = Uuid(raw_buffer[56:56+16])
        self.hostname = raw_buffer[72:72+16].decode("ascii").strip()
        self.entry_number = struct.unpack("<L", raw_buffer[88:88+4])[0]
        self.unknown2 = struct.unpack("<L", raw_buffer[92:92+4])[0]
        self.unknown3 = struct.unpack("<L", raw_buffer[96:96+4])[0]
        self.last_modification_time = Helpers.datetime_from_u64(
            struct.unpack("<Q", raw_buffer[100:100+8])[0]
        )
        self.pin_status = struct.unpack("<L", raw_buffer[108:108+4])[0]
        self.path_size = struct.unpack("<H", raw_buffer[112:112+2])[0] * 2
        self.path = raw_buffer[114:114+self.path_size].decode('utf-16le')

    def as_dict(self):
        record = OrderedDict([
            ("droid_volume_identifier", str(self.droid_volume_identifier)),
            ("droid_file_identifier", str(self.droid_file_identifier)),
            ("birth_droid_volume_identifier", str(self.birth_droid_volume_identifier)),
            ("birth_droid_file_identifier", str(self.birth_droid_file_identifier)),
            ("hostname", self.hostname),
            ("entry_number", self.entry_number),
            ("last_modification_time", self.last_modification_time),
            ("pin_status", self.pin_status),
            ("path", self.path),
        ])
        return record


class DestListEntryV3(object):
    def __init__(self, raw_buffer):
        self.unknown1 = raw_buffer[0:8].hex()
        self.droid_volume_identifier = Uuid(raw_buffer[8:8 + 16])
        self.droid_file_identifier = Uuid(raw_buffer[24:24 + 16])
        self.birth_droid_volume_identifier = Uuid(raw_buffer[40:40 + 16])
        self.birth_droid_file_identifier = Uuid(raw_buffer[56:56 + 16])
        self.hostname = raw_buffer[72:72 + 16].decode("ascii").strip()
        self.entry_number = struct.unpack("<L", raw_buffer[88:88 + 4])[0]
        self.unknown2 = struct.unpack("<L", raw_buffer[92:92 + 4])[0]
        self.unknown3 = struct.unpack("<L", raw_buffer[96:96 + 4])[0]
        self.last_modification_time = Helpers.datetime_from_u64(
            struct.unpack("<Q", raw_buffer[100:100 + 8])[0]
        )
        self.pin_status = struct.unpack("<L", raw_buffer[108:108 + 4])[0]
        self.unknown4 = struct.unpack("<L", raw_buffer[112:112+4])[0]
        self.unknown5 = struct.unpack("<L", raw_buffer[116:116+4])[0]
        self.unknown6 = struct.unpack("<Q", raw_buffer[120:120+8])[0]
        self.path_size = struct.unpack("<H", raw_buffer[128:128+2])[0] * 2
        self.path = raw_buffer[130:130+self.path_size].decode('utf-16le')

    def as_dict(self):
        record = OrderedDict([
            ("droid_volume_identifier", str(self.droid_volume_identifier)),
            ("droid_file_identifier", str(self.droid_file_identifier)),
            ("birth_droid_volume_identifier", str(self.birth_droid_volume_identifier)),
            ("birth_droid_file_identifier", str(self.birth_droid_file_identifier)),
            ("hostname", self.hostname),
            ("entry_number", self.entry_number),
            ("last_modification_time", self.last_modification_time),
            ("pin_status", self.pin_status),
            ("path", self.path),
        ])
        return record


class DestListEntryV4(object):
    def __init__(self, raw_buffer):
        self.unknown1 = raw_buffer[0:8].hex()
        self.droid_volume_identifier = Uuid(raw_buffer[8:8 + 16])
        self.droid_file_identifier = Uuid(raw_buffer[24:24 + 16])
        self.birth_droid_volume_identifier = Uuid(raw_buffer[40:40 + 16])
        self.birth_droid_file_identifier = Uuid(raw_buffer[56:56 + 16])
        self.hostname = raw_buffer[72:72 + 16].decode("ascii").strip()
        self.entry_number = struct.unpack("<L", raw_buffer[88:88 + 4])[0]
        self.unknown2 = struct.unpack("<L", raw_buffer[92:92 + 4])[0]
        self.unknown3 = struct.unpack("<L", raw_buffer[96:96 + 4])[0]
        self.last_modification_time = Helpers.datetime_from_u64(
            struct.unpack("<Q", raw_buffer[100:100 + 8])[0]
        )
        self.pin_status = struct.unpack("<L", raw_buffer[108:108 + 4])[0]
        self.unknown4 = struct.unpack("<L", raw_buffer[112:112+4])[0]
        self.unknown5 = struct.unpack("<L", raw_buffer[116:116+4])[0]
        self.unknown6 = struct.unpack("<Q", raw_buffer[120:120+8])[0]
        self.path_size = struct.unpack("<H", raw_buffer[128:128+2])[0] * 2
        self.path = raw_buffer[130:130+self.path_size].decode('utf-16le')

    def as_dict(self):
        record = OrderedDict([
            ("droid_volume_identifier", str(self.droid_volume_identifier)),
            ("droid_file_identifier", str(self.droid_file_identifier)),
            ("birth_droid_volume_identifier", str(self.birth_droid_volume_identifier)),
            ("birth_droid_file_identifier", str(self.birth_droid_file_identifier)),
            ("hostname", self.hostname),
            ("entry_number", self.entry_number),
            ("last_modification_time", self.last_modification_time),
            ("pin_status", self.pin_status),
            ("path", self.path),
        ])
        return record


class FileReference(object):
    def __init__(self, raw_buf):
        self.reference = struct.unpack("<Q", raw_buf)[0]
        self.entry = struct.unpack("<Lxx", raw_buf[:6])[0]
        self.sequence = struct.unpack("<H", raw_buf[6:8])[0]

    @staticmethod
    def from_u64(u64):
        return FileReference(
            struct.pack("<Q", u64)
        )

    def as_dict(self):
        record = OrderedDict([
            ('reference', self.reference),
            ('entry', self.entry),
            ('sequence', self.sequence),
        ])
        return record


class LnkValidationError(Exception):
    def __init__(self, message):
        super(LnkValidationError, self).__init__(message)


class UriItem(object):
    def __init__(self, item):
        self.item = item


class TypeRootFolder(object):
    def __init__(self, root_folder):
        self.root_folder = root_folder

    def as_dict(self):
        record = OrderedDict([])
        record['shell_folder_identifier'] = self.root_folder.get_shell_folder_identifier()
        return OrderedDict([
            ('root_folder', record)
        ])


class TypeFileEntryExtension(object):
    def __init__(self, file_entry_extension):
        self.file_entry_extension = file_entry_extension

    def as_dict(self):
        record = OrderedDict([])
        access_t_int = self.file_entry_extension.get_access_time_as_integer()
        create_t_int = self.file_entry_extension.get_creation_time_as_integer()

        record['access_time'] = None
        record['creation_time'] = None

        if access_t_int > 0:
            record['access_time'] = self.file_entry_extension.get_access_time()

        if create_t_int > 0:
            record['creation_time'] = self.file_entry_extension.get_creation_time()

        file_reference = self.file_entry_extension.get_file_reference()
        record['file_reference'] = None
        if file_reference:
            record['file_reference'] = FileReference.from_u64(
                file_reference
            ).as_dict()

        record['localized_name'] = self.file_entry_extension.get_localized_name()
        record['long_name'] = self.file_entry_extension.get_long_name()
        return record


class TypeFileEntry(object):
    def __init__(self, file_entry):
        self.file_entry = file_entry

    def as_dict(self):
        record = OrderedDict([])
        record['file_size'] = self.file_entry.get_file_size()

        modify_t_int = self.file_entry.get_modification_time_as_integer()

        record['modification_time'] = None
        if modify_t_int > 0:
            record['modification_time'] = self.file_entry.get_modification_time()

        record['name'] = self.file_entry.get_name()
        return OrderedDict([
            ('file_entry', record)
        ])


class TypeNetworkLocation(object):
    def __init__(self, network_location):
        self.network_location = network_location

    def as_dict(self):
        record = OrderedDict([])
        record['comments'] = self.network_location.get_comments()
        record['description'] = self.network_location.get_description()
        record['location'] = self.network_location.get_location()
        return OrderedDict([
            ('network_location', record)
        ])


class TypeVolume(object):
    def __init__(self, volume):
        self.volume = volume

    def as_dict(self):
        record = OrderedDict([])
        record['identifier'] = self.volume.get_identifier()
        record['name'] = self.volume.get_name()
        record['shell_folder_identifier'] = self.volume.get_shell_folder_identifier()
        return OrderedDict([
            ('volume', record)
        ])


class ShellItem(object):
    def __init__(self, libfwsi_item):
        self.libfwsi_item = libfwsi_item

    def as_dict(self):
        record = OrderedDict([])
        record['class_type_str'] = type(self.libfwsi_item).__name__
        record['class_type_int'] = self.libfwsi_item.get_class_type()

        this = get_shell_type(
            self.libfwsi_item
        )
        if this:
            record.update(
                this.as_dict()
            )

        count = self.libfwsi_item.get_number_of_extension_blocks()
        record['extension_count'] = count
        record['extensions'] = []
        for i in range(count):
            e_block = self.libfwsi_item.get_extension_block(i)
            extension_type = type(e_block).__name__

            if extension_type == 'file_entry_extension':
                e_block = TypeFileEntryExtension(e_block)
                record['extensions'].append(
                    e_block.as_dict()
                )
            else:
                logging.debug("unhandled extension block class type: {}".format(extension_type))

        return record


class TargetData(object):
    def __init__(self, data, codepage='cp1252'):
        self.parsed = False
        self.shell_items = pyfwsi.item_list()
        try:
            self.shell_items.copy_from_byte_stream(
                data, ascii_codepage=codepage
            )
            self.parsed = True
        except Exception as error:
            logging.error('Shell items not parsed: {}'.format(error))

    def as_list(self):
        shell_item_dicts = []
        if self.parsed:
            count = self.shell_items.get_number_of_items()
            for i in range(count):
                libfwsi_item = self.shell_items.get_item(i)
                shell_item = ShellItem(
                    libfwsi_item
                )

                shell_item_dicts.append(
                    shell_item.as_dict()
                )

        return shell_item_dicts


class CustomDestination(object):
    SIGNATURE_END = b"\xAB\xFB\xBF\xBA"
    LINK_SIGNATURE_RE = b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"

    def __init__(self, file_io, source_description):
        self.file_io = file_io
        self.source_description = source_description
        self.lnk_files = []

        self._enum_link_files()

    def _enum_link_files(self):
        raw_data = self.file_io.read()
        for match in re.finditer(CustomDestination.LINK_SIGNATURE_RE, raw_data):
            start_offset = match.start()

            byte_io = io.BytesIO(
                raw_data[start_offset:]
            )
            lnk_parser = LnkParser(
                byte_io, "{} [{}]".format(self.source_description, start_offset)
            )
            self.lnk_files.append(
                lnk_parser
            )

    def iter_dicts(self):
        for lnk_parser in self.lnk_files:
            yield lnk_parser.as_dict()


class AutomaticDestination(object):
    def __init__(self, file_io, source_description):
        self.file_io = file_io
        self.source_description = source_description
        self.lnk_files = []

        self._enum_link_files()

    def _enum_link_files(self):
        olecf_file = None
        if pyolecf.check_file_signature_file_object(self.file_io):
            olecf_file = pyolecf.file()
            olecf_file.open_file_object(
                self.file_io
            )

            dest_list_item = olecf_file.root_item.get_sub_item_by_name(
                'DestList'
            )
            data_size = dest_list_item.get_size()
            raw_data = dest_list_item.read(data_size)

            dest_list = DestList(raw_data)
            for entry in dest_list:
                item_name = hex(entry.entry_number)[2:]
                link_item = olecf_file.root_item.get_sub_item_by_name(
                    item_name
                )
                data_size = link_item.get_size()
                raw_data = link_item.read(data_size)

                byte_io = io.BytesIO(
                    raw_data
                )
                lnk_parser = LnkParser(
                    byte_io, "{} [{}]".format(self.source_description, item_name), jmp_info=entry.as_dict()
                )

                self.lnk_files.append(
                    lnk_parser
                )
        else:
            logging.debug("{} does not have valid olecf signature.".format(
                self.source_description
            ))

    def iter_dicts(self):
        for lnk_parser in self.lnk_files:
            yield lnk_parser.as_dict()


class JumplistParser(object):
    def __init__(self, file_io, source_description, jumplist_type):
        self.file_io = file_io
        self.source_description = source_description
        self.hash = None
        self._enum_hash()
        self.jumplist_type = jumplist_type

    def _enum_hash(self):
        base_name = os.path.basename(
            self.source_description
        )
        match = re.search('([A-Fa-f0-9]{16})\.(automatic|custom)Destinations-ms', base_name)
        if match:
            self.hash = match.group(1)

    def parse(self):
        if self.jumplist_type == 'automatic':
            ad = AutomaticDestination(
                self.file_io, self.source_description
            )

            for dict_entry in ad.iter_dicts():
                dict_entry.update({"app_hash": self.hash})
                print(json.dumps(dict_entry, cls=ComplexEncoder))
        elif self.jumplist_type == 'custom':
            cd = CustomDestination(
                self.file_io, self.source_description
            )

            for dict_entry in cd.iter_dicts():
                dict_entry.update({"app_hash": self.hash})
                print(json.dumps(dict_entry, cls=ComplexEncoder))
        else:
            logging.error("unknown jumplist type: {}".format(self.jumplist_type))


class LnkParser(object):
    def __init__(self, file_io, source_description, jmp_info=None):
        self.file_io = file_io
        self.source_description = source_description
        self.jmp_info = jmp_info
        self.lnk_file = None

        if pylnk.check_file_signature_file_object(self.file_io):
            self.lnk_file = pylnk.file()
            self.lnk_file.open_file_object(
                self.file_io
            )
        else:
            message = "File object has invalid signature: {}".format(self.source_description)
            raise(LnkValidationError(message))

        target_data = self.lnk_file.get_link_target_identifier_data()
        self.target_data = TargetData(
            target_data, codepage=self.lnk_file.get_ascii_codepage().decode('ascii')
        )

    def as_dict(self):
        record = OrderedDict([])
        record['meta_source'] = self.source_description
        if self.jmp_info:
            record['jmp_info'] = self.jmp_info
        record['ascii_codepage'] = self.lnk_file.get_ascii_codepage().decode('ascii', 'replace')
        record['birth_droid_file_identifier'] = self.lnk_file.get_birth_droid_file_identifier()
        record['birth_droid_volume_identifier'] = self.lnk_file.get_birth_droid_volume_identifier()
        record['command_line_arguments'] = self.lnk_file.get_command_line_arguments()
        record['data_flags'] = self.lnk_file.get_data_flags()
        record['description'] = self.lnk_file.get_description()
        record['drive_serial_number'] = format_serial(self.lnk_file.get_drive_serial_number())
        record['drive_type'] = self.lnk_file.get_drive_type()
        record['droid_file_identifier'] = self.lnk_file.get_droid_file_identifier()
        record['droid_volume_identifier'] = self.lnk_file.get_droid_volume_identifier()
        record['environment_variables_location'] = self.lnk_file.get_environment_variables_location()
        record['file_access_time'] = self.lnk_file.get_file_access_time()
        record['file_attribute_flags'] = self.lnk_file.get_file_attribute_flags()
        record['file_creation_time'] = self.lnk_file.get_file_creation_time()
        record['file_modification_time'] = self.lnk_file.get_file_modification_time()
        record['file_size'] = self.lnk_file.get_file_size()
        record['hot_key_value'] = self.lnk_file.get_hot_key_value()
        record['icon_index'] = self.lnk_file.get_icon_index()
        record['icon_location'] = self.lnk_file.get_icon_location()
        record['local_path'] = self.lnk_file.get_local_path()
        record['machine_identifier'] = self.lnk_file.get_machine_identifier()
        record['network_path'] = self.lnk_file.get_network_path()
        record['relative_path'] = self.lnk_file.get_relative_path()
        record['show_window_value'] = self.lnk_file.get_show_window_value()
        record['volume_label'] = self.lnk_file.get_volume_label()
        record['working_directory'] = self.lnk_file.get_working_directory()
        record['target_data'] = self.target_data.as_list()
        return record


class LnkHandler(object):
    def __init__(self, source, file_io):
        self.source = source
        self.file_io = file_io
        self.type = None
        self.jump_type = None

        s_lower = source.lower()

        if s_lower.endswith("automaticdestinations-ms"):
            self.type = "jumplist"
            self.jump_type = "automatic"
        elif s_lower.endswith("customdestinations-ms"):
            self.type = "jumplist"
            self.jump_type = "custom"
        elif s_lower.endswith(".lnk"):
            self.type = "link"
        else:
            raise(Exception("Source extension not lnk or destinations-ms: {}".format(s_lower)))

    def parse(self):
        logging.debug("[starting] Parsing {}".format(self.source))
        if self.type == 'link':
            try:
                lnk_parser = LnkParser(
                    self.file_io, self.source
                )
            except LnkValidationError as error:
                logging.error("Invalid Link File: {}".format(error))
                return
            except Exception as error:
                logging.error("Error Parsing Link File: {}".format(error))
                return

            print(json.dumps(lnk_parser.as_dict(), cls=ComplexEncoder))
        elif self.type == 'jumplist':
            try:
                jmp_parser = JumplistParser(
                    self.file_io, self.source, self.jump_type
                )
                jmp_parser.parse()
            except Exception as error:
                logging.error("Error Parsing Jumplist File: {}".format(error))
                return
        else:
            raise(Exception("Source type not handled: {}".format(self.type)))
        logging.debug("[finished] Parsing {}".format(self.source))

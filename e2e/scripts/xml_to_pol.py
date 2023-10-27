import argparse
import base64
import logging
import os
import types

import xml.etree.ElementTree as etree

from samba.dcerpc import preg
from samba.dcerpc import misc
from samba.gp_parse.gp_pol import GPPolParser
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Convert XML files to POL using Samba (or the other way around)')
    parser.add_argument('path', type=str,
                        help='Root path to search for XML files (will recurse into subdirectories), or exact path to convert')
    parser.add_argument('-r', '--reverse', action='store_true',
                        help='Search for POL files and convert them to XML')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    extension = '.pol.xml' if not args.reverse else '.pol'

    if os.path.isfile(args.path):
        pol_files = [args.path]
        args.reverse = args.path.endswith('.pol')
    else:
        pol_files = file_list(args.path, extension)
        logging.info('Found %d %s files' % (len(pol_files), extension))

    for pol_file in pol_files:
        try:
            if args.reverse:
                logging.info('Converting %s to XML' % pol_file)
                convert_to_xml(pol_file)
            else:
                logging.info('Converting %s to POL' % pol_file)
                convert_to_pol(pol_file)
        except Exception as e:
            logging.error('Failed to convert %s' % pol_file)
            logging.exception(e)
            continue

def file_list(path, extension):
    files = []
    for root, _, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith(extension):
                files.append(os.path.join(root, filename))
    return files

def convert_to_xml(pol_file):
    parser = GPPolParser()
    with open(pol_file, 'rb') as f:
        pol_data = f.read()
    parser.parse(pol_data)

    # We append .xml when we convert from POL
    xml_file = pol_file + '.xml'
    logging.debug('Writing XML to %s' % xml_file)
    parser.write_xml(xml_file)

def convert_to_pol(xml_file):
    # This is a hack to pick up an unreleased Samba fix for properly parsing
    # empty MULTI_SZ values
    def _load_xml(self, root):
        self.pol_file = preg.file()
        self.pol_file.header.signature = root.attrib['signature']
        self.pol_file.header.version = int(root.attrib['version'])
        self.pol_file.num_entries = int(root.attrib['num_entries'])

        entries = []
        for e in root.findall('Entry'):
            entry = preg.entry()
            entry_type = int(e.attrib['type'])

            entry.type = entry_type

            entry.keyname = e.find('Key').text
            value_name = e.find('ValueName').text
            if value_name is None:
                value_name = ''

            entry.valuename = value_name

            if misc.REG_MULTI_SZ == entry_type:
                values = [x.text for x in e.findall('Value')]
                if values == [None]:
                    data = u'\x00'
                else:
                    data = u'\x00'.join(values) + u'\x00\x00'
                entry.data = data.encode('utf-16le')
            elif (misc.REG_NONE == entry_type):
                pass
            elif (misc.REG_SZ == entry_type or
                  misc.REG_EXPAND_SZ == entry_type):
                string_val = e.find('Value').text
                if string_val is None:
                    string_val = ''
                entry.data = string_val
            elif (misc.REG_DWORD == entry_type or
                  misc.REG_DWORD_BIG_ENDIAN == entry_type or
                  misc.REG_QWORD == entry_type):
                entry.data = int(e.find('Value').text)
            else: # REG UNKNOWN or REG_BINARY
                entry.data = base64.b64decode(e.find('Value').text)

            entries.append(entry)

        self.pol_file.entries = entries

    parser = GPPolParser()

    # Override load_xml method with our custom one
    parser.load_xml = types.MethodType(_load_xml, parser)
    with open(xml_file, 'r') as f:
        xml_data = f.read()
    parser.load_xml(etree.fromstring(xml_data.strip()))

    # We remove .xml when we convert from XML
    xml_path = Path(xml_file)
    pol_file = xml_path.as_posix()[:-len(''.join(xml_path.suffixes))] + '.pol'
    logging.debug('Writing POL to %s' % pol_file)
    parser.write_binary(pol_file)


if __name__ == '__main__':
    main()

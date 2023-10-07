import argparse
import logging
import os
import re

import xml.etree.ElementTree as etree

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
    parser = GPPolParser()
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

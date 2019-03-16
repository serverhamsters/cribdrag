#!/usr/bin/python3

##########################
# cribdrag - An interactive crib dragging tool
# Daniel Crowley
# Copyright (C) 2013 Trustwave Holdings, Inc.
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
##########################
# Changelog
# 2019-03-16 Ported to Python 3 ~ Robbe Van der Gucht
##########################

import argparse
from binascii import unhexlify

parser = argparse.ArgumentParser(description='xorstrings is a utility which comes with cribdrag, the interactive crib dragging tool. xorstrings takes two ASCII hex encoded strings and XORs them together. This can be useful when cryptanalyzing ciphertext produced by the One Time Pad algorithm or a stream cipher when keys are reused, as one can XOR two ciphertexts together and then crib drag across the result, which is both plaintexts XORed together.')
parser.add_argument('-h1', '--hex1', help='Data encoded in an ASCII hex format (ie. -h1 ABC would be 414243)')
parser.add_argument('-h2', '--hex2', help='Data encoded in an ASCII hex format (ie. -h2 ABC would be 414243)')
parser.add_argument('-f1', '--file1', help='File with raw bytes')
parser.add_argument('-f2', '--file2', help='File with raw bytes')
parser.add_argument('-s', '--separator', 
    help='Separate hex bytes (ie. \':\' would return 41:42:43',
    default='')
args = parser.parse_args()

bstr1 = b""
bstr2 = b""

if args.hex1:
    bstr1 = unhexlify(args.hex1)
elif args.file1:
    with open(args.file1, 'rb') as fh:
        bstr1 = fh.read()
else:
    raise Exception("Must provide either --hex1 or --file1 argument")

if args.hex2:
    bstr2 = unhexlify(args.hex2)
elif args.file2:
    with open(args.file2, 'rb') as fh:
        bstr2 = fh.read()
else:
    raise Exception("Must provide either --hex1 or --file1 argument")

result = b''
for b1, b2 in zip(bstr1, bstr2):
    result += bytes([b1 ^ b2])

print((args.separator).join("{:02x}".format(b) for b in result))

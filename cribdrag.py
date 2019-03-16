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


import re
import argparse
from binascii import unhexlify
from itertools import zip_longest

def crib_test(cipher_bstr, crib_bstr):
    results = []
    crib_len = len(crib_bstr)
    positions = len(cipher_bstr) - crib_len + 1
    for index in range(positions):
        single_result = b""
        for a, b in zip(cipher_bstr[index: index + crib_len], crib_bstr):
            single_result += bytes([a ^ b])
        results.append(single_result)
    return results

def to_printable_ascii(bstr):
    result = ''
    printable_ascii = range(32, 127)
    for b in list(bstr):
        if b in printable_ascii:
            result += chr(b)
        else:
            result += '�'
    return result

def print_display(display_cipher, display_key):
    print("MSG |", end=" ")
    print(display_cipher)
    print("KEY |", end=" ")
    print(display_key)

parser = argparse.ArgumentParser(
    description='cribdrag, the interactive crib dragging script, allows you to interactively decrypt ciphertext using a cryptanalytic technique known as "crib dragging". This technique involves applying a known or guessed part of the plaintext (a "crib") to every possible position of the ciphertext. By analyzing the result of each operation and the likelihood of the result being a successful decryption based on the expected format and language of the plaintext one can recover the plaintext by making educated guesses and adaptive application of the crib dragging technique.'
)
parser.add_argument('ciphertext', 
    help='Ciphertext, encoded in an ASCII hex format (ie. ABC would be 414243)'
)
parser.add_argument('-c', '--charset', 
    help='A regex-style character set to be used to identify best candidates for successful decryption (ex: for alphanumeric characters and spaces, use "a-zA-Z0-9 ")', 
    default=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
)
args = parser.parse_args()

cipher_bstr = unhexlify(args.ciphertext)
cipher_len = len(cipher_bstr)

display_cipher = "." * cipher_len
display_key = "." * cipher_len

while True :
    print_display(display_cipher, display_key)

    crib_str = input("Please enter crib > ")
    crib_bstr = crib_str.encode("ascii")
    crib_len = len(crib_bstr)

    results = crib_test(cipher_bstr, crib_bstr)
    results_len = len(results)

    nr_columns = 4
    columns = list()
    for i in range(nr_columns):
        columns.append(list())
    
    for index, result in enumerate(results, 1):
        printable_result = to_printable_ascii(result)
        
        if (re.search("^[" + args.charset + "]+$", printable_result)):
            mark = "*"
        else:
            mark = " "

        column_ind = index // int((cipher_len) / nr_columns)
        columns[column_ind].append("{mark} {index:3d} {xorred}".format(
            mark=mark,
            index=index,
            xorred=printable_result
        ))
            
    for a,b,c,d in zip_longest(*columns, fillvalue=(" " * len(columns[0][0]))):
        print("{} | {} | {} | {}".format(a,b,c,d))
    response = input("\nEnter a position, 'none', or 'end' to quit > ")

    try:
        index = int(response) - 1
        if index < results_len and index >= 0:
            while True:
                message_or_key = input("Is this crib part of the message or" + 
                    " key? Please enter 'message' or 'key' > ")
                if message_or_key == 'message':
                    display_cipher = (
                        display_cipher[:index] + 
                        crib_str + 
                        display_cipher[index+crib_len:]
                    )
                    display_key = (
                        display_key[:index] +
                        to_printable_ascii(results[index]) +
                        display_key[index+crib_len:]
                    )
                    break
                elif message_or_key == 'key':
                    display_cipher = (
                        display_cipher[:index] + 
                        to_printable_ascii(results[index]) +
                        display_cipher[index+crib_len:]
                    )
                    display_key = (
                        display_key[:index] +
                        crib_str +
                        display_key[index+crib_len:]
                    )
                    break
                else:
                    print("Invalid response. Try again.")
        else:
            print("Number must be less than {}".format(results_len))
    except ValueError:
        if response == 'end':
            print_display(display_cipher, display_key)
            break
        elif response == 'none':
            print("No changes made.")
        else:
            print("Invalid entry.")



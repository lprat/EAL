#! /usr/bin/env python
# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright © 2011-2020 ANSSI. All Rights Reserved.
#
# Author(s): Ryad Benadjila (ANSSI), Sebastien Chapiron (ANSSI), Arnaud Ebalard (ANSSI)
#

import logging
import struct
import re
import sys
from datetime import datetime
from pathlib import Path
from shlex import quote
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

rsa_oaep_oid =          re.compile(re.escape(bytes.fromhex('06092a864886f70d010107')))
rsa_encryption_oid =    re.compile(re.escape(bytes.fromhex('06092a864886f70d0101010500')))
pkcs7_data_oid =        bytes.fromhex('06092a864886f70d010701301d')
unstream_cmd = (Path(__file__).parent / 'unstream').resolve()
openssl_cmd = 'openssl'

def decode_oid(oid):
    if not (oid[0] == 6 and oid[1] == len(oid) - 2):
        raise ValueError(f'Not an OID: {oid}')
    oid = oid[2:]

    res = []
    res.append(int(oid[0] / 40))
    res.append(oid[0] - (40 * res[0]))
    oid = oid[1:]

    cur = 0
    while oid:
        tmp = oid[0]
        cur <<= 7
        if (tmp & 0x80):
            cur |= tmp - 0x80
        else:
            cur |= tmp
            res.append(cur)
            cur = 0
        oid = oid[1:]

    return ".".join(map(lambda x: "%d" % x, res))


def decrypt_archive_python(archive_path: Path, private_key: Path, output_file: Path):
    ## Load the private key and the base 64 ciphertext.
    private_key = RSA.importKey(open(private_key, 'rb').read())

    # We grab the beginning of the file so that we can extract the
    # various information we need (RSA-encrypted symmetric key,
    # encryption algorithm, etc). After having decrypted the key
    # we open the file at the right offset (beginning of octet
    # strings containing data) and decrypt the data.
    s = open(archive_path, 'rb').read(50*1024)

    symkey = None
    # First try with RSAES-OAEP OID
    for match in rsa_oaep_oid.finditer(s):
        # Next we should have 04|82|len|rsaencryptedsymkey
        key_offset = match.end() + 4
        encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
        encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
        try:
            symkey = PKCS1_OAEP.new(private_key).decrypt(encsymkey)
            logging.debug('Successfully decrypted symmetric key found with RSAES-OAEP OID at offset 0x%x', match.start())
            break
        except ValueError as e:
            pass
    else:
        logging.warning('Failed to decrypt any of the %d symmetric keys found with RSAES-OAEP OID',
                        len(rsa_oaep_oid.findall(s)))

    if not symkey:
        # Try with rsaEncryption OID
        for match in rsa_encryption_oid.finditer(s):
            # Next we should have 04|82|len|rsaencryptedsymkey
            key_offset = match.end() + 2
            encsymkeylen = struct.unpack(">H", s[key_offset: key_offset + 2])[0]
            encsymkey = s[key_offset + 2: key_offset + 2 + encsymkeylen]
            try:
                symkey = PKCS1_OAEP.new(private_key).decrypt(encsymkey)
                logging.debug('Successfully decrypted symmetric key found with rsaEncryption OID at offset 0x%x',
                              match.start())
                break
            except ValueError as e:
                pass
        else:
            logging.warning('Failed to decrypt any of the %d symmetric keys found with rsaEncryption OID',
                            len(rsa_encryption_oid.findall(s)))

    if not symkey:
        return False

    # Next, we jump to pkcs7-data OID. It is followed by two bytes
    # before the beginning of symmetric encryption method OID
    pkcs7_offset = s.find(pkcs7_data_oid) + len(pkcs7_data_oid)
    oidlen = s[pkcs7_offset + 1]
    sym_enc_oid = decode_oid(s[pkcs7_offset:pkcs7_offset + oidlen + 2])

    # Next elements is IV
    iv_offset = pkcs7_offset + oidlen + 2
    ivlen = s[iv_offset + 1]
    iv = s[iv_offset + 2 : iv_offset + ivlen + 2]

    if sym_enc_oid == "2.16.840.1.101.3.4.1.42":  # AES 256 CBC
        if len(symkey) != 32:
            logging.critical('Expected a 256 bit key for AES-256-CBC (got %d instead)', len(symkey) * 8)
            return False
        logging.debug('Using AES-256-CBC (OID  %s) for decryption', sym_enc_oid)
        enc_alg = AES.new(symkey, AES.MODE_CBC, iv)
    elif sym_enc_oid == "2.16.840.1.101.3.4.1.2":  # AES 128 CBC
        if len(symkey) != 16:
            logging.critical('Expected a 128 bit key for AES-128-CBC (got %d instead)', len(symkey) * 8)
            return False
        logging.debug('Using AES-128-CBC (OID  %s) for decryption', sym_enc_oid)
        enc_alg = AES.new(symkey, AES.MODE_CBC, iv)
    else:
        logging.critical('Unknown encryption algorithm w/ OID %s', sym_enc_oid)
        return False

    # We should now have all our octet strings providing encrypted
    # content after a A0 80
    content_offset = iv_offset + ivlen + 2
    if s[content_offset:content_offset + 2] != b'\xA0\x80':
        logging.critical('File does not match what we expected (\\xA0\\x80) at offset %d: %s. Found at %d',
                         content_offset, s[content_offset-10:content_offset + 20].hex(), s[813:].find(b'\xA0\x80'))
        return False
    out = open(output_file, "wb")
    with open(archive_path, 'rb') as f:
        f.seek(content_offset + 2)
        logging.debug('Writing to %s', output_file)
        # Remove output file if it exists so that unstream does not fail
        #output_file.unlink(missing_ok=True)

        try:
            t, c = struct.unpack("BB", f.read(2))
            prev = bytes()
            while t == 0x04:
                if c & 0x80 == 0:
                    oslen = c
                else:
                    oslen = int.from_bytes(f.read(c & 0x7f), byteorder='big')
                # Revisit to deal with incomplete read
                out.write(prev)
                prev = enc_alg.decrypt(f.read(oslen))
                h = f.read(2)
                if not h:
                    break
                t, c = struct.unpack("BB", h)

            # We need to remove possible padding from last decrypted chunk
            if len(prev) > 1 and len(prev) > prev[-1]:
                prev = prev[:-prev[-1]]
                out.write(prev)
        except BrokenPipeError:
            pass

    out.close()
    return True


if len(sys.argv) != 4:
    print("Usage: <key path> <encrypted file> <output file>")
    sys.exit(0)
print("Uncrypt file :"+sys.argv[2]+" with key:"+sys.argv[1])
res = decrypt_archive_python(sys.argv[2], sys.argv[1], sys.argv[3])

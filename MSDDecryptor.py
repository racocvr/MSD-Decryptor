#
# MSD Decryptor is a tool that extracts the files from an ecrypted .msd file
#
# (c) MrB 2020
#

import hashlib
import os
import struct
import sys
from collections import namedtuple
from os import path
import binascii
from Crypto.Cipher import AES

def hexdump(s):
    n = 0
    for l in range(0, len(s), 16):
        b = memoryview(s)[l:l+16]
        s1 = " ".join([f"{i:02x}" for i in b])  # hex string
        s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values

        s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison

        print(f"{n * 16:08x}  {s1:<48}  {s2}")

        n += 1

def remove_padding(s):
    return memoryview(s)[:-ord(s[len(s) - 1:])].tobytes()

def decrypt_header(f, header, aeskey):
    f.seek(header.offset, 0)

    decrypted_header_crc32, = struct.unpack("<I", f.read(4))
    encrypted_header_crc32, = struct.unpack("<I", f.read(4))

    assert f.read(8).decode('ascii') == 'Salted__',"'Salted__' header not found"

    # read the salt and md5 it
    iv = hashlib.md5(f.read(8))

    print('decrypting header', header.model, 'with aeskey:', aeskey.hex(), 'and iv:', iv.hexdigest())

    encrypted = f.read(header.length - 16 - 8)
    assert binascii.crc32(encrypted) == encrypted_header_crc32, 'encrypted header crc32 mismatch (file corrupt!)'

    aes = AES.new(aeskey, AES.MODE_CBC, iv.digest())
    decrypted = remove_padding(aes.decrypt(encrypted))
    assert binascii.crc32(decrypted) == decrypted_header_crc32, 'decrypted header crc32 mismatch (wrong aeskey!)'

    return decrypted


def savebin(filename, content):
    total = len(content)
    written = 0
    chunksize = 1024

    with open(filename, 'wb') as f:
        for i in range(0, total, chunksize):
            written += f.write(memoryview(content)[i:i + chunksize].tobytes())
            done = int(25 * written / total)
            print('\rsaving {} [{}{}]'.format(os.path.basename(filename), '█' * done, '.' * (25 - done)), end='')
        print(' done! (%d bytes)' % written)


def readstring(mv, pos):
    label = bytearray()
    b = mv[pos]
    while b:
        label.append(b)
        pos += 1
        b = mv[pos]

    return label.decode('ascii'), pos + 1


def readword(mv, pos, size):
    if size == 1: return struct.unpack("<B", mv[pos:pos + 1])[0], pos + 1
    elif size == 2: return struct.unpack("<H", mv[pos:pos + 2])[0], pos + 2
    elif size == 4: return struct.unpack("<I", mv[pos:pos + 4])[0], pos + 4
    elif size == 8: return struct.unpack("<Q", mv[pos:pos + 8])[0], pos + 8
    else:
        return -1, 0

def readbytes(mv, pos, size):
    return mv[pos:pos + size].tobytes(), pos + size


def decrypt_itemfile(item, filename, salt, aeskey, f):
    iv = hashlib.md5(salt)

    print('decrypting file', item.id, filename, 'with aeskey:', aeskey.hex(), 'and iv:', iv.hexdigest())

    total = item.length
    written = 0
    chunksize = 1024 * 1024
    f.seek(item.offset, 0)

    aes = AES.new(aeskey, AES.MODE_CBC, iv.digest())

    with open(path.dirname(f.name) + os.path.sep + filename, 'wb+') as wf:
        while written < total:
            if total - written < chunksize:
                chunksize = total - written
            written += wf.write(aes.decrypt(f.read(chunksize)))
            done = int(25 * written / total)
            print('\rsaving {} [{}{}]'.format(filename, '█' * done, '.' * (25 - done)), end='')

        wf.seek(-1, os.SEEK_END)
        padding, = wf.read(1)
        wf.seek(-padding, os.SEEK_END)
        wf.truncate()
        wf.close()

        print(' done! (%d bytes)' % (written - padding))


def parse_outree_item(itemdata, items, aeskey, f):
    mv = memoryview(itemdata)
    pos = 0
    #hexdump(mv)

    itemtype, pos = readword(mv, pos, 4)

    if itemtype == 1:
        itemid, pos = readword(mv, pos + 1, 4)

        # we skip 33 bytes of data, hoping no variable length items are ever put before our itemfilename
        itemfilenamelen, pos = readword(mv, pos + 33, 1)
        itemfilename, pos = readbytes(mv, pos, itemfilenamelen)

        # again we skip 38 bytes same as before
        itemsaltlen, pos = readword(mv, pos + 38, 1)
        itemsalt, pos = readbytes(mv, pos, 8)

        #print('tree item size: {}, type: file, filename: {}, salt: {}'.
        #      format(itemsize, itemfilename.decode('ascii'), itemsalt.hex()))
        decrypt_itemfile(items[itemid - 1], itemfilename.decode('ascii'), itemsalt, aeskey, f)

    elif itemtype == 2:
        modellen, pos = readword(mv, pos + 19, 1)
        model, pos = readbytes(mv, pos, modellen)
        majorver, pos = readword(mv, pos, 2)
        minorver, pos = readword(mv, pos, 2)

        print('firmware version: {}-{}.{} '.format(model.decode('ascii'), majorver, minorver))


def parse_outree(outree, items, aeskey, f):
    mv = memoryview(outree)
    pos = 0

    crc32, pos = readword(mv, pos, 4)      # crc32 of itemsPublicRSAKey.txt used
    siglen, pos = readword(mv, pos, 2)
    signature, pos = readbytes(mv, pos, siglen)

    # read OUSWFileVersionDesc
    label, pos = readstring(mv, pos)
    #print('tree label:', label)

    ntreeitems, pos = readword(mv, pos, 4)
    #print('tree items #:', ntreeitems)

    for i in range(ntreeitems):
        treeitemsize, pos =  readword(mv, pos + 1, 4)
        treeitemdata, pos = readbytes(mv, pos, treeitemsize)
        parse_outree_item(treeitemdata, items, aeskey, f)


def parse_msdfile(filename, aeskey):
    with open(filename, 'rb') as f:
        # read the magic value
        magic = f.read(6)
        assert magic.decode('ascii') == 'MSDU11', 'wrong magic found: %s' % magic.decode('ascii')

        # read the msd header crc32
        crc32, = struct.unpack("<I", f.read(4))

        # skip 1 unknown qword
        f.seek(8, 1)

        # read the number of items available
        nitems, = struct.unpack("<I", f.read(4))
        assert nitems > 0, 'wrong nitems found: %d' % nitems

        print('magic:', magic, 'crc32:', hex(crc32), 'nitems:', nitems)

        # read items
        Item = namedtuple('Item', 'id offset length')
        items = []
        for i in range(nitems):
            items.append(Item(id=struct.unpack("<I", f.read(4))[0],
                              offset=struct.unpack("<Q", f.read(8))[0],
                              length=struct.unpack("<Q", f.read(8))[0]))
            #print('item', i, items[i])

        # read the number of headers available
        nheaders, = struct.unpack("<I", f.read(4))
        assert nheaders >= 0, 'wrong nheaders found: %d' % nheaders

        print('nheaders:', nheaders)

        # read the headers
        Header = namedtuple('Header', 'offset length model')
        headers = []
        for i in range(nheaders):
            offset, =struct.unpack("<Q", f.read(8))
            length, =struct.unpack("<I", f.read(4))
            modellen, = struct.unpack("<B", f.read(1))
            headers.append(Header(offset, length, f.read(modellen).decode('ascii')))

            #print('header', i, headers[i])

        # compute the crc32 of the msd header
        pos = f.tell()
        f.seek(18, 0)
        computedcrc32 = binascii.crc32(f.read(pos - 18))
        assert crc32 == computedcrc32, 'msd file header crc32 mismatch, crc32: ' + \
                                          hex(crc32) + ' != computed crc32: ' + hex(computedcrc32)

        # decrypt using the provided aeskey and the md5(salt) as iv
        for i in range(nheaders):
            decrypted = decrypt_header(f, headers[i], aeskey)
            #hexdump(decrypted)
            #savebin(path.dirname(filename) + os.path.sep + 'OUTreeHeader%d.bin' % i, decrypted)
            parse_outree(decrypted, items, aeskey, f)

    return 'done'


def main(argv):
    if len(argv) < 3:
        print('usage: ', path.basename(argv[1]), '<upgrade.msd> <aeskey>')
    elif not path.exists(argv[1]):
        print('msd file not found:', argv[1])
    elif len(argv[2]) != 32:
        print('wrong aeskey length! expected 16 bytes in hex form')
    else:
        print(parse_msdfile(argv[1], bytes.fromhex(argv[2])))


if __name__ == "__main__":
    main(sys.argv)


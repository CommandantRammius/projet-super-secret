#!/usr/bin/python3

__copyright__ = "Copyright 2023, Hack'Lantique™"
__license__ = "IMT"
__flag__ = "HACKLANTIQUE{A_1A_p0ur5uiT3_d'oCtoBr3_rOu9E}"

import os
import sys
import random
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long

import pickle

filename = sys.argv[1]
with open(filename, "rb") as f:
    data = f.read()


def derivation(buf, n):
    ret = buf[:]
    for i in range(n):
        x = b''
        for c in ret:
            x += b'%X' % c
        h = SHA256.new()
        h.update(x)
        ret = h.digest()
    return ret

def getNeighboursContacts(coords):
    global MAX_X
    global MAX_Y
    contacts = []
    if(coords["x"] < MAX_X):
        contact = {"layer": coords["layer"], "x": (coords["x"]+1), "y": coords["y"]}
        if(isWire(contact)):
            contacts.append(contact)
    if(coords["x"] > 0):
        contact = {"layer": coords["layer"], "x": (coords["x"]-1), "y": coords["y"]}
        if(isWire(contact)):
            contacts.append(contact)
    if(coords["y"] < MAX_Y):
        contact = {"layer": coords["layer"], "x": coords["x"], "y": (coords["y"]+1)}
        if(isWire(contact)):
            contacts.append(contact)
    if(coords["y"] > 0):
        contact = {"layer": coords["layer"], "x": coords["x"], "y": (coords["y"]-1)}
        if(isWire(contact)):
            contacts.append(contact)

    return contacts

def getNextPossibleCoords(coords, coordsToAvoid):
    nextCoords = getNeighboursContacts(coords)
    if(isWireEdge(coords)):
        nextCoords = nextCoords + getOtherLayersContact(coords)
    filteredNextCoords = []
    for coord in nextCoords:
        canBeTravelled = True
        for avoidCoord in coordsToAvoid:
            if(compareCoords(coord, avoidCoord)):
                canBeTravelled = False
        if(canBeTravelled):
            filteredNextCoords.append(coord)
    return filteredNextCoords


def getLongestPathFrom(coords):
    if(not(isWire(coords))):
        return []

    longestPath = []
    def travelNextCoord(pathDone):
        nonlocal longestPath

        nextPossibleCoords = getNextPossibleCoords(pathDone[-1], pathDone)

        if(len(nextPossibleCoords) == 0):
            if(len(pathDone) > len(longestPath)):
                longestPath = pathDone
            return pathDone

        for coord in nextPossibleCoords:
            newPath = pathDone + [coord]
            travelNextCoord(newPath)

    travelNextCoord([coords])

    return longestPath
  

N = 107432977185950290289416741649199945007638843008792997324779404768244225092561607689734944711696600299859344233412431621988246274123128221489877283833331324476987804803364145697393742458543765224900352789688640134043078256150509010956909235120830127504153969333426545234882130547530909701987904659156965893001
P = 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676298471525243254143375622365552296949413920679290535717172319562064308937342567483690486592868352763021360051776130919666984258847567032959931761686072492923
Q = 68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605

NB = "Tm90ZSDgIG1vaS1t6m1lIDogcGVuc2VyIOAgY29tbWVudGVyIGxlIGNvZGUgcGFyY2UgcXUnb24gY29tcHJlbmRzIHJpZW4="

if __name__ == '__main__':
    session_key = bytes([random.SystemRandom().getrandbits(8) for __ in range(32)])
    nsk = bytes_to_long(session_key)


    s = nsk % 1000000000
    x = []
    for i in range(8):
        x += [s >> 16]
        s = ((s * 123456789) + 23) % 2147483648
    nh = (-8 * x[0] + 4 * x[2] - x[4] + 2 * x[5] + 7 * x[7]) % (2**15)
    nc = (-x[0] + 2 * x[1] + 2 * x[2] - 2 * x[3] + 6 * x[4] - 11 * x[5] - 6 * x[6] - 2 * x[7]) % (2**15)


    len_plain = len(data)
    h = SHA256.new()
    h.update(data)
    hash_plain = h.hexdigest()


    len_crypt = ((len_plain + 7) // 8) * 8
    padding = b'\xff' * (len_crypt - len_plain)

    buf = session_key + bytes(filename, encoding='utf8')
    
    new_name = derivation(buf, nh).hex() + '.vault'
    cipher_key = derivation(buf, nc)
    

    iv = bytes([0, 0, 0, 0, 0, 0, 0, 0])
    cipher = Blowfish.new(cipher_key, Blowfish.MODE_CBC, iv)
    crypt_data = cipher.encrypt(data + padding)

    encrypted_session_key = pow(nsk, 65537, N)
    locked_file = { "crypt_data" : crypt_data, "length" : len_plain, "encrypted_session_key": encrypted_session_key, "hash" : hash_plain, "name" : filename}


    with open(new_name, "wb") as f:
        f.write(pickle.dumps(locked_file))

    os.unlink(filename)
    print(f'{filename} -> {new_name}')

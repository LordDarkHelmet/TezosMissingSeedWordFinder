#!/usr/bin/env python3
# Copyright (c) 2019 LordDarkHelmet (https://github.com/LordDarkHelmet)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import re
import os
import sys
import json
import hashlib
import binascii
import argparse
import math
import unicodedata
#import base58

#apt -y install python3-pysodium
import pysodium


#from pyblake2 import blake2b


PY3 = sys.version_info[0] == 3

if not PY3:
    print("This program requires Python 3.6+ to run.")
    sys.exit(0)



bip39WordFileDirectory = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])) , "bip-0039")


# from https://github.com/trezor/python-mnemonic/blob/master/mnemonic/mnemonic.py
def normalize_string(txt):
        if isinstance(txt, str if sys.version < "3" else bytes):
            utxt = txt.decode("utf8")
        elif isinstance(txt, unicode if sys.version < "3" else str):  # noqa: F821
            utxt = txt
        else:
            raise TypeError("String value expected")

        return unicodedata.normalize("NFKD", utxt)



def getSeedWordListFromString(seedWords):
    return [seedWord for seedWord in normalize_string(seedWords).split(' ')]



### Check if the seed words form a valid checksum. All ICO wallets have a valid seed checksum.
### See Josh McIntyre's post for a good walkthrough. https://jmcintyre.net/?p=180
def isValidChecksumForMnemonic(seedWords, wordList):
    myWords = getSeedWordListFromString(seedWords)
    myWordPosBinString = ""

    #Must be a multiple of 3 to be valid. Currently the set of [12, 15, 18, 21, 24] are valid, but future versions may be different. Hence leaving it as % 3 instead of if len(myWords) not in [12, 15, 18, 21, 24]:
    if (len(myWords) % 3 != 0):
        sys.stderr.write("[WARNING] Seed Words Must be a Multple of 3!\n")
        return False

    #check to ensure that seed words are on the list, and to get a string for the checksum process
    try:
        for t in myWords:
            myWordPosBinString += str(bin(wordList.index(t)))[2:].zfill(11);
    except ValueError:
        sys.stderr.write("[WARNING] Seed Word Not Found On Word List!\n")
        return False

    lenOfChecksum = len(myWordPosBinString) // 33
    lenOfBody = lenOfChecksum * 32

    seedWordBody = myWordPosBinString[:lenOfBody]
    seedWordChecksum = myWordPosBinString[-lenOfChecksum:] #get just the checksum

    binaryRepresentationOfBody = binascii.unhexlify(hex(int(seedWordBody, 2))[2:].zfill(lenOfChecksum * 8))
    generatedChecksum = bin(int(hashlib.sha256(binaryRepresentationOfBody).hexdigest(), 16))[2:].zfill(256)[: lenOfChecksum]

    if generatedChecksum != seedWordChecksum:
#        sys.stderr.write("[WARNING] Invalid mnemonic checksum! Check your seed words!\n")
        return False
    return True


### Check to see if it is a valid Mnemonic
def isValidMnemonic(seedWords):
    myWords = getSeedWordListFromString(seedWords)
    # Get a list of all avalible languages
    expectedNuberOfFiles = 8
    languageList = [str(os.path.join(bip39WordFileDirectory , files)) for files in os.listdir(bip39WordFileDirectory) if files.endswith(".txt")]
    if (len(languageList) < expectedNuberOfFiles):
        sys.stderr.write("[WARNING] Language List Error. Language files not detected! Files found=" + str(len(languageList)) + " expecting at least " + str(expectedNuberOfFiles) + "\n")
        return False

    for languageFile in languageList:
         f = open(languageFile, 'r', encoding="utf-8")
         x = f.readlines()
         f.close()
         bip39Words = list(map(lambda s: normalize_string(s.strip()), x))
         if len(bip39Words) != 2048:
            sys.stderr.write("[WARNING] Error in " + languageFile + " " + str(len(bip39Words)) + " words detected. There should be exactly 2048 words!\n")
            return False

         #Do all the words exist in the selected list? if so validate it.
         if set(myWords).issubset(bip39Words):
            if isValidChecksumForMnemonic(seedWords, bip39Words):
                return True
            return False

    sys.stderr.write("[WARNING] Provided Seed Words Are Not Valid Seed Words!\n")
    return False


### Check to see if it is a valid Mnemonic
def repairSingleMissingWordInMnemonic(seedWords, myAddress, myPassword, myEmail):
    myWords = getSeedWordListFromString(seedWords)
    if len(myWords) != 14:
        print("There must be 14 seed words, Please check your inputs. If you have more than one missing seed word contact the developer. ")
        return False

    # Get a list of all avalible languages
    expectedNuberOfFiles = 8
    languageList = [str(os.path.join(bip39WordFileDirectory , files)) for files in os.listdir(bip39WordFileDirectory) if files.endswith(".txt")]
    if (len(languageList) < expectedNuberOfFiles):
        sys.stderr.write("[WARNING] Language List Error. Language files not detected! Files found=" + str(len(languageList)) + " expecting at least " + str(expectedNuberOfFiles) + "\n")
        return False
    numberOfValidCombos = 0
    listOfValidMnemonics = []
    for languageFile in languageList:
         f = open(languageFile, 'r', encoding="utf-8")
         x = f.readlines()
         f.close()
         bip39Words = list(map(lambda s: normalize_string(s.strip()), x))
         if len(bip39Words) != 2048:
            sys.stderr.write("[WARNING] Error in " + languageFile + " " + str(len(bip39Words)) + " words detected. There should be exactly 2048 words!\n")
            return False

         #Do all the words exist in the selected list? if so validate it.
         if set(myWords).issubset(bip39Words):
            print("Using BIP-0039 Language File: " + languageFile)
            print("Prepare List of Valid Mnemonic Combinations . . . This should take less than a minute...")
            #OK At this point you have validated the words in the mnemonic are valid, now we want to add all the words in slot 1, then in slot 2, ... each time checking is the checksum is valid. if it is print out the info.
            for x in range(15):
                print("Checking Seed Word Location " + str(x))
                for y in bip39Words:
                    myWords.insert(x, y)
                    if isValidChecksumForMnemonic(" ".join(myWords), bip39Words):
                        #print (" ".join(myWords))
                        listOfValidMnemonics.append(" ".join(myWords))
                        numberOfValidCombos = numberOfValidCombos + 1
                    myWords.pop(x)
    print ("Number of Valid Combinations: " + str(numberOfValidCombos))

    if numberOfValidCombos == 0:
       print("Hmmmm... zero valid combinations??? Check your seed words, did you mispell something? Contact the developer for additional help")
       return False

    print ("")
    print ("Performing Validation Check for " + str(numberOfValidCombos) + " possibilities. This should take less than a minute...")
    for z in listOfValidMnemonics:
        if doesGeneratedMatchOriginal(z, myPassword, myEmail, myAddress) == True:
            print("")
            print("DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
            print("DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
            print("")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("Valid Combination Found!!!!!!!!!!!!!!!!!!!!!!!")
            print("Address:    " + myAddress)
            print("Password:   " + myEmail)
            print("Email:      " + myPassword)
            print("Seed Words: " + z)
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("")
            print("DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
            print("DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
            print("")
            print("MOVE FUNDS TO A NEW ADDRESS. DO NOT REUSE YOUR PASSWORD OR SEED WORDS")
            print("MOVE FUNDS TO A NEW ADDRESS. DO NOT REUSE YOUR PASSWORD OR SEED WORDS")
            print("")
            print("Using this program exposes your password. It is now in your history, if someone is able to access this computer they can get to your funds. Please move your funds.")
            print("")
            print("This application was requested by members of the Tezos XTZ Recovery Telegram Group.")
            print("For Tezos recovery assistance please visit: https://t.me/xtzrecovery")
            print("")
            print("Feel free to contact me for requests or assistance")
            print("LordDarkHelmet")
            print("GitHub: https://github.com/LordDarkHelmet/")
            print("")
            print("Donation Addresses")
            print("BTC:   33DxcicBuN7wvqByLfmHH9FC9AvuEa3cGh")
            print("Tezos: tz1WYZrE1Lhd5cgh4vzUhJB1UBNGEdekbskQ")
            return True

    print("")
    print("Hmmm... we didn't find it. Please check your inputs. Are you sure you are using the correct password, capitalization, ... Please contact us on Telegram for further help. https://t.me/xtzrecovery")
    return False




def mnemonic_and_passphraase_to_seed(key: str, passphrase: str, email: str):

#    key = scrub_input(key)
#    mnemonic = u' '.join(key).lower()

    key = key.lower()
    mnemonic = unicodedata.normalize('NFKD', ' '.join(key.lower().split()))
    mnemonic = u' '.join(key.split())
    mnemonic = scrub_input(mnemonic)
    passphrase = scrub_input(passphrase)
    #"mnemonic" needs to be the first part of the seed.
    email = scrub_input("mnemonic" + email)
    salt = unicodedata.normalize("NFKD", (email + passphrase).decode("utf8")).encode("utf8")
    seed =  hashlib.pbkdf2_hmac(hash_name='sha512', password=mnemonic, salt=salt, iterations=2048, dklen=64)
    return seed


#from https://github.com/murbard/pytezos/blob/master/pytezos/encoding.py
def tb(l):
    return b''.join(map(lambda x: x.to_bytes(1, 'big'), l))

                  #    Encoded   |               Decoded             |
                  # prefix | len | prefix                      | len | Data type
base58_encodings = [(b"tz1",   36,   tb([6, 161, 159]),            20,   u"ed25519 public key hash")]


def scrub_input(v) -> bytes:
    if isinstance(v, str) and not isinstance(v, bytes):
        try:
            _ = int(v, 16)
        except ValueError:
            v = v.encode('ascii')
        else:
            if v.startswith('0x'):
                v = v[2:]
            v = bytes.fromhex(v)

    if not isinstance(v, bytes):
        raise TypeError(
            "a bytes-like object is required (also str), not '%s'" %
            type(v).__name__)

    return v


def base58_encode(v: bytes, prefix: bytes) -> bytes:
    try:
        encoding = next(
            encoding
            for encoding in base58_encodings
            if len(v) == encoding[3] and prefix == encoding[0]
        )
    except StopIteration:
        raise ValueError('Invalid encoding, prefix or length mismatch.')

    return b58encode_check(encoding[2] + v)


#from: https://github.com/keis/base58/blob/master/base58.py
BITCOIN_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode_check(v, alphabet=BITCOIN_ALPHABET):
    """
    Encode a string using Base58 with a 4 character checksum
    """

    digest = hashlib.sha256(hashlib.sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet=alphabet)


def b58encode_int(i, default_one=True, alphabet=BITCOIN_ALPHABET):
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    while i:
        i, idx = divmod(i, 58)
        string = alphabet[idx:idx+1] + string
    return string

if bytes == str:  # python2
    iseq, bseq, buffer = (
        lambda s: map(ord, s),
        lambda s: ''.join(map(chr, s)),
        lambda s: s,
    )
else:  # python3
    iseq, bseq, buffer = (
        lambda s: s,
        bytes,
        lambda s: s.buffer,
    )


def b58encode(v, alphabet=BITCOIN_ALPHABET):
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in iseq(reversed(v)):
        acc += p * c
        p = p << 8
    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * nPad + result





def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]


def bin_to_b58check(inp, magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)


def doesGeneratedMatchOriginal(myMnemonic, myPassword, myEmail, myAddress):
    try:
        seed = mnemonic_and_passphraase_to_seed(myMnemonic, myPassword, myEmail)
    except:
        print('bad')
        sys.exit(1)

    pk, sk = pysodium.crypto_sign_seed_keypair(seed[0:32])
    pkh = hashlib.blake2b(pk, digest_size=20).digest()
    prefix = {b'ed': b'tz1', b'sp': b'tz2', b'p2': b'tz3'}[b"ed"]
    test = base58_encode(pkh, prefix).decode()
    if myAddress == test:
#        print("Found the right seed words!")
#        print("Address: " + myAddress)
#        print(myMnemonic)
        return True
    return False


print("")
print("Tezos Missing Seed Word Finder - A single missing seed word in an unknown location")
print("")
print("DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
print("Values printed to the screen and in your computer's history can be viewed. Please use in an offline environment.")
print("DO NOT SHARE ANY INFORMATION  WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
print("")
print("This application was requested by members of the Tezos XTZ Recovery Telegram Group.")
print("For Tezos recovery assistance please visit: https://t.me/xtzrecovery")
print("")
print("Please use this on a computer that is not connected to the internet in any way.")
print("Once you have recovered your seed words, please move your funds.")
print("")


parser = argparse.ArgumentParser(description='Tezos Missing Seed Word Finder')
args, myArgs = parser.parse_known_args()

if len(myArgs) != 4:
    sys.stderr.write("Usage: %s \'mnemonic data (15 words)\' \'email\' \'public key\'\n" % sys.argv[0])
    sys.stderr.write("""\nExample: python3 %s 'piece tag panther file invest spread rural rude rally sweet lava goose tuna confirm' 'TezosHelp@outlook.com' 'tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ' '@Fluffy1234'\n""" % sys.argv[0])
    sys.exit(-1)

userMnemonic, userEmail, userAddress, userPassword = sys.argv[1:5]


print("")
print('Using known Values to perform an Internal Check.')

myMnemonic="piece tag panther file invest spread rural rude rally sweet lava goose apology tuna confirm"
myPassword="@Fluffy1234"
myAddress="tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ"
myEmail="TezosHelp@outlook.com"

if  isValidMnemonic(myMnemonic) == False:
    print("You Should Not See this");

if doesGeneratedMatchOriginal(myMnemonic, myPassword, myEmail, myAddress) == False:
    print("There is an issue with the code, please contact the developer")
    sys.exit(1)

print("Test Validation Complete, all systems go!")



print("")
print("")
print("Starting Mnemonic Check")
print("")
print("DO NOT SHARE THIS INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER")
print("Input Values")
print("Address:  " + userAddress)
print("Mnemonic: " + userMnemonic)
print("Email:    " + userEmail)
print("Password: " + userPassword)
print("")
print("Number of Possible Combinations: " + str(2048 * 15))
repairSingleMissingWordInMnemonic(userMnemonic, userAddress, userPassword, userEmail)

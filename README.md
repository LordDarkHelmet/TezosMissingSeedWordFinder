# Tezos Missing Mnemonic Seed Word Finder
Recover your Tezos if you are missing a single seed word

Did you forget to write down one of your seed words? This utility will recover your seed word! Even if you don't know which one is missing.

<b>This program needs your private information to work. Please run on a computer not connected in any way to the internet. Please move your funds to a new address as soon as you recover your information. Your private information is printed to the screen and stored in your computer's history. Again, USE ON A DISCONNECTED COMPUTER THAT YOU CAN DESTROY!</b>

OK, at this point you know to protect your information. Please use caution. 

This program has been tested on Ubuntu 18.04 and Python 3.6.7

## Prerequisites
 
You need to install the following for this program to work. Please do this before you use this script. Once you are done with the prerequisites, please disconnect from the internet. 

Python3: This runs the script<br>
pysodium: This has libraries needed to validate your information

Type in the following to install the prerequisites:
```
sudo apt-get -y update
sudo apt-get -y python3
suod apt -y install python3-pysodium
```

## TezosMissingSeedWordFinder.py

Please note that running this requires you to type in your private information, that information is stored in your OS. Please use on an offline computer that you can destroy. It is your responsibility to keep your information safe. 


Usage: 
```
TezosMissingSeedWordFinder.py 'mnemonic data (14 words)' 'email' 'public key'
```

Example: 
```
python3 TezosMissingSeedWordFinder.py 'piece tag panther file invest spread rural rude rally sweet lava goose tuna confirm' 'TezosHelp@outlook.com' 'tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ' '@Fluffy1234'
```

Results:
```
python3 TezosMissingSeedWordFinder.py 'piece tag panther file invest spread rural rude rally sweet lava goose tuna confirm' 'TezosHelp@outlook.com' 'tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ' '@Fluffy1234'

Tezos Missing Seed Word Finder - A single missing seed word in an unknown location

DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER
Values printed to the screen and in your computer's history can be viewed. Please use in an offline environment.
DO NOT SHARE ANY INFORMATION  WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER

This application was requested by members of the Tezos XTZ Recovery Telegram Group.
For Tezos recovery assistance please visit: https://t.me/xtzrecovery

Please use this on a computer that is not connected to the internet in any way.
Once you have recovered your seed words, please move your funds.


Using known Values to perform an Internal Check.
Test Validation Complete, all systems go!


Starting Mnemonic Check

DO NOT SHARE THIS INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER
Input Values
Address:  tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ
Mnemonic: piece tag panther file invest spread rural rude rally sweet lava goose tuna confirm
Email:    TezosHelp@outlook.com
Password: @Fluffy1234

Number of Possible Combinations: 30720
Using BIP-0039 Language File: /root/bip-0039/english.txt
Prepare List of Valid Mnemonic Combinations . . . This should take less than a minute...
Checking Seed Word Location 0
Checking Seed Word Location 1
Checking Seed Word Location 2
Checking Seed Word Location 3
Checking Seed Word Location 4
Checking Seed Word Location 5
Checking Seed Word Location 6
Checking Seed Word Location 7
Checking Seed Word Location 8
Checking Seed Word Location 9
Checking Seed Word Location 10
Checking Seed Word Location 11
Checking Seed Word Location 12
Checking Seed Word Location 13
Checking Seed Word Location 14
Number of Valid Combinations: 998

Performing Validation Check for 998 possibilities. This should take less than a minute...

DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER
DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Valid Combination Found!!!!!!!!!!!!!!!!!!!!!!!
Address:    tz1KsyixYbCqXrr8vjckmLDLYBkwGWv46PYZ
Password:   TezosHelp@outlook.com
Email:      @Fluffy1234
Seed Words: piece tag panther file invest spread rural rude rally sweet lava goose apology tuna confirm
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER
DO NOT SHARE ANY INFORMATION WITH ANYONE FOR ANY REASON, NOT EVEN THE DEVEOPER

MOVE FUNDS TO A NEW ADDRESS. DO NOT REUSE YOUR PASSWORD OR SEED WORDS
MOVE FUNDS TO A NEW ADDRESS. DO NOT REUSE YOUR PASSWORD OR SEED WORDS

Using this program exposes your password. It is now in your history, if someone is able to access this computer they can get to your funds. Please move your funds.

This application was requested by members of the Tezos XTZ Recovery Telegram Group.
For Tezos recovery assistance please visit: https://t.me/xtzrecovery

Feel free to contact me for requests or assistance
LordDarkHelmet
GitHub: https://github.com/LordDarkHelmet/

Donation Addresses
BTC:   33DxcicBuN7wvqByLfmHH9FC9AvuEa3cGh
Tezos: tz1WYZrE1Lhd5cgh4vzUhJB1UBNGEdekbskQ
```

## Need More Assistance?

This application was requested by members of the Tezos XTZ Recovery Telegram Group. <br>
For Tezos recovery assistance please visit: https://t.me/xtzrecovery 

Feel free to contact me for requests or assistance

### Donations are welcome:
BTC:   33DxcicBuN7wvqByLfmHH9FC9AvuEa3cGh <br>
Tezos: tz1WYZrE1Lhd5cgh4vzUhJB1UBNGEdekbskQ

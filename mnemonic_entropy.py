#!/usr/bin/env python

################################################################################################
#
# 2019.06.01 - Adapted by vogelito from GlacierScript, part of the Glacier Protocol
# (http://glacierprotocol.org) as part of a broader project to adapt the Glacier Protocol for
# multi-chain and multi-device support
#
################################################################################################

# standard Python libraries
import argparse
import sys
import hashlib
from hashlib import sha256
import subprocess


################################################################################################
#
# Minor helper functions
#
################################################################################################

def hash_sha256(s):
    """A thin wrapper around the hashlib SHA256 library to provide a more functional interface"""
    m = sha256()
    m.update(s)
    return m.hexdigest()


################################################################################################
#
# Read & validate random data from the user
#
################################################################################################

def validate_rng_seed(seed, min_length):
    """
    Validates random hexadecimal seed
    returns => <boolean>

    seed: <string> hex string to be validated
    min_length: <int> number of characters required.  > 0
    """

    if len(seed) < min_length:
        print "Error: Computer entropy must be at least {0} characters long".format(min_length)
        return False

    if len(seed) % 2 != 0:
        print "Error: Computer entropy must contain an even number of characters."
        return False

    try:
        int(seed, 16)
    except ValueError:
        print "Error: Illegal character. Computer entropy must be composed of hexadecimal characters only (0-9, a-f)."
        return False

    return True

def read_rng_seed_interactive(min_length):
    """
    Reads random seed (of at least min_length hexadecimal characters) from standard input
    returns => string

    min_length: <int> minimum number of bytes in the seed.
    """

    char_length = min_length * 2

    def ask_for_rng_seed(length):
        print "Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(length)

    ask_for_rng_seed(char_length)
    seed = raw_input()
    seed = unchunk(seed)

    while not validate_rng_seed(seed, char_length):
        ask_for_rng_seed(char_length)
        seed = raw_input()
        seed = unchunk(seed)

    return seed

def validate_dice_seed(dice, min_length):
    """
    Validates dice data (i.e. ensures all digits are between 1 and 6).
    returns => <boolean>

    dice: <string> representing list of dice rolls (e.g. "5261435236...")
    """

    if len(dice) < min_length:
        print "Error: You must provide at least {0} dice rolls".format(min_length)
        return False

    for die in dice:
        try:
            i = int(die)
            if i < 1 or i > 6:
                print "Error: Dice rolls must be between 1 and 6."
                return False
        except ValueError:
            print "Error: Dice rolls must be numbers between 1 and 6"
            return False

    return True

def read_dice_seed_interactive(min_length):
    """
    Reads min_length dice rolls from standard input, as a string of consecutive integers
    Returns a string representing the dice rolls
    returns => <string>

    min_length: <int> number of dice rolls required.  > 0.
    """

    def ask_for_dice_seed(x):
        print "Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:".format(x)

    ask_for_dice_seed(min_length)
    dice = raw_input()
    dice = unchunk(dice)

    while not validate_dice_seed(dice, min_length):
        ask_for_dice_seed(min_length)
        dice = raw_input()
        dice = unchunk(dice)

    return dice


################################################################################################
#
# private key generation
#
################################################################################################

def xor_hex_strings(str1, str2):
    """
    Return xor of two hex strings.
    An XOR of two pieces of data will be as random as the input with the most randomness.
    We can thus combine two entropy sources in this way as a safeguard against one source being
    compromised in some way.
    For details, see http://crypto.stackexchange.com/a/17660

    returns => <string> in hex format
    """
    if len(str1) != len(str2):
        raise Exception("tried to xor strings of unequal length")
    str1_dec = int(str1, 16)
    str2_dec = int(str2, 16)

    xored = str1_dec ^ str2_dec

    return "{:0{}x}".format(xored, len(str1))


################################################################################################
#
# User sanity checking
#
################################################################################################

def yes_no_interactive():
    def confirm_prompt():
        return raw_input("Confirm? (y/n): ")

    confirm = confirm_prompt()

    while True:
        if confirm.upper() == "Y":
            return True
        if confirm.upper() == "N":
            return False
        else:
            print "You must enter y (for yes) or n (for no)."
            confirm = confirm_prompt()

def safety_checklist():

    checks = [
        "Are you running this on a computer WITHOUT a network connection of any kind?",
        "Have the wireless cards in this computer been physically removed?",
        "Are you running on battery power?",
        "Are you running on an operating system booted from a USB drive?",
        "Is your screen hidden from view of windows, cameras, and other people?",
        "Are smartphones and all other nearby devices turned off and in a Faraday bag?"]

    for check in checks:
        answer = raw_input(check + " (y/n)?")
        if answer.upper() != "Y":
            print "\n Safety check failed. Exiting."
            sys.exit()


################################################################################################
#
# Main "entropy" function
#
################################################################################################

def unchunk(string):
    """
    Remove spaces in string
    """
    return string.replace(" ", "")

def chunk_string(string, length):
    """
    Splits a string into chunks of [length] characters, for easy human readability
    Source: https://stackoverflow.com/a/18854817/11031317
    """
    return (string[0+i:length+i] for i in range(0, len(string), length))

def random(length):
    """
    Generate a random string for the user from /dev/random
    """

    print "Making a random data string...."
    print "If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n"

    seed = subprocess.check_output("xxd -l {} -p /dev/random".format(length), shell=True)
    seed = seed.replace('\n', '')

    computer_entropy = " ".join(chunk_string(seed, 4))
    print("Generated Computer entropy: {0}\n\n".format(computer_entropy))
    return unchunk(computer_entropy)

def entropy(dice_seed_length=62, rng_seed_length=20, integrity_mode=False):
    """
    Generate entropy for BIP39 generation
    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required
    """
    print integrity_mode
    #safety_checklist()

    print "Creating entropy for BIP39 derivation..."

    dice_seed_string = read_dice_seed_interactive(dice_seed_length)
    dice_seed_hash = hash_sha256(dice_seed_string)

    computer_entropy = rng_seed_string = read_rng_seed_interactive(rng_seed_length) if integrity_mode else random(rng_seed_length)
    rng_seed_hash = hash_sha256(computer_entropy)

    # back to hex string
    hex_private_key = xor_hex_strings(dice_seed_hash, rng_seed_hash)

    print("Generated Entropy (copy this string into bip39-standalone.html): {0}\n".format(hex_private_key))


################################################################################################
#
# main function
#
# Show help, or execute one of the three main routines: entropy
#
################################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('program', choices=['entropy'])

    parser.add_argument("-d", "--dice", type=int,
                        help="The minimum number of dice rolls to use for entropy when generating private keys (default: 62)", default=62)
    parser.add_argument("-r", "--rng", type=int,
                        help="Minimum number of 8-bit bytes to use for computer entropy when generating private keys (default: 20)", default=20)
    parser.add_argument('-i', '--integrity', action='store_true', help='Allows for user provided computer entropy for integrity checking')

    args = parser.parse_args()
    integrity_mode = args.integrity

    if args.program == "entropy":
        entropy(args.dice, args.rng, integrity_mode)

'''
Created on Mar 28, 2014

@author: stefan
'''

from cryptanalysis import search
from ciphers import (simon, speck, simonlinear, keccak, keccakdiff,
                     siphash, simonrk, chaskeymachalf, simonkeyrc,
                     ketje, ascon, salsa, chacha, skinny, present,
                     midori, lblock, sparx, sparxround, fly, fly4bit,
                     twine, noekeon, prince, mantis)

from config import PATH_STP, PATH_CRYPTOMINISAT, PATH_BOOLECTOR

from argparse import ArgumentParser, RawTextHelpFormatter

import yaml
import os
import sys


def startsearch(tool_parameters):
    """
    Starts the search tool for the given parameters
    """

    cipher_suite = {"simon" : simon.SimonCipher(),
                    "speck" : speck.SpeckCipher(),
                    "simonlinear" : simonlinear.SimonLinearCipher(),
                    "keccak" : keccak.KeccakCipher(),
                    "keccakdiff" : keccakdiff.KeccakDiffCipher(),
                    "ketje" : ketje.KetjeCipher(),
                    "siphash" : siphash.SipHashCipher(),
                    "simonrk" : simonrk.SimonRkCipher(),
                    "simonkeyrc" : simonkeyrc.SimonKeyRcCipher(),
                    "chaskeyhalf" : chaskeymachalf.ChasKeyMacHalf(),
                    "ascon" : ascon.AsconCipher(),
                    "salsa" : salsa.SalsaCipher(),
                    "chacha" : chacha.ChaChaCipher(),
                    "skinny" : skinny.SkinnyCipher(),
                    "present" : present.PresentCipher(),
                    "midori" : midori.MidoriCipher(),
                    "lblock" : lblock.LBlockCipher(),
                    "sparx" : sparx.SPARXCipher(),
                    "sparxround" : sparxround.SPARXRoundCipher(),
                    "fly" : fly.FlyCipher(),
                    "fly4bit" : fly4bit.Fly4BitCipher(),
                    "twine" : twine.TwineCipher(),
                    "noekeon" : noekeon.NoekeonCipher(),
                    "prince" : prince.PrinceCipher(),
                    "mantis" : mantis.MantisCipher()}
    cipher = None

    if tool_parameters["cipher"] in cipher_suite:
        cipher = cipher_suite[tool_parameters["cipher"]]
    else:
        print("Cipher not supported!")
        sys.stdout.flush()
        return

    # Handle program flow
    if tool_parameters["mode"] == 0:
        search.findMinWeightCharacteristic(cipher, tool_parameters)
    elif tool_parameters["mode"] == 1:
        search.searchCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 2:
        search.findAllCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 3:
        search.findBestConstants(cipher, tool_parameters)
    elif tool_parameters["mode"] == 4:
        search.computeProbabilityOfDifferentials(cipher, tool_parameters)
    elif tool_parameters["mode"] == 5:
        search.findOptimalTrailsMatsui(cipher, tool_parameters)

    return

def checkenviroment():
    """
    Basic checks if the enviroment is set up correctly
    """

    if not os.path.exists("./tmp/"):
        os.makedirs("./tmp/")

    if not os.path.exists(PATH_STP):
        print("ERROR: Could not find STP binary, please check config.py")
        sys.stdout.flush()
        exit()

    if not os.path.exists(PATH_CRYPTOMINISAT):
        print("WARNING: Could not find CRYPTOMINISAT binary, please check "
              "config.py.")
        sys.stdout.flush()

    if not os.path.exists(PATH_BOOLECTOR):
        print("WARNING: Could not find BOOLECTOR binary, \"--boolector\" "
              "option not available.")
        sys.stdout.flush()

    return


def loadparameters(args):
    """
    Get parameters from the argument list and inputfile.
    """
    # Load default values
    params = {"cipher" : "simon",
              "rounds" : 5,
              "mode" : 0,
              "wordsize" : 16,
              "blocksize" : 64,
              "sweight" : 0,
              "endweight" : 1000,
              "iterative" : False,
              "boolector" : False,
              "dot" : None,
              "latex" : None,
              "nummessages" : 1,
              "timelimit" : -1,
              "fixedVariables" : {},
              "blockedCharacteristics" : [],
              "rate" : 160,
              "capacity" : 240}

    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], 'r') as input_file:
            doc = yaml.load(input_file)
            params.update(doc)
            if "fixedVariables" in doc:
                fixed_vars = {}
                for variable in doc["fixedVariables"]:
                    fixed_vars = dict(list(fixed_vars.items()) +
                                      list(variable.items()))
                params["fixedVariables"] = fixed_vars

    # Override parameters if they are set on commandline
    if args.cipher:
        params["cipher"] = args.cipher[0]

    if args.rounds:
        params["rounds"] = args.rounds[0]

    if args.wordsize:
        params["wordsize"] = args.wordsize[0]

    if args.blocksize:
        params["blocksize"] = args.blocksize[0]

    if args.sweight:
        params["sweight"] = args.sweight[0]

    if args.endweight:
        params["endweight"] = args.endweight[0]

    if args.mode:
        params["mode"] = args.mode[0]

    if args.timelimit:
        params["timelimit"] = args.timelimit[0]

    if args.iterative:
        params["iterative"] = args.iterative

    if args.boolector:
        params["boolector"] = args.boolector

    if args.nummessages:
        params["nummessages"] = args.nummessages[0]

    if args.dot:
        params["dot"] = args.dot[0]

    if args.latex:
        params["latex"] = args.latex[0]

    if args.rate:
        params["rate"] = int(args.rate[0])

    if args.capacity:
        params["capacity"] = int(args.capacity[0])

    return params


def main():
    """
    Parse the arguments and start the request functionality with the provided
    parameters.
    """
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "trail in a cryptopgrahic primitive"
                                        "using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--cipher', nargs=1, help="Options: simon, speck, ...")
    parser.add_argument('--sweight', nargs=1, type=int,
                        help="Starting weight for the trail search.")
    parser.add_argument('--endweight', nargs=1, type=int,
                        help="Stop search after reaching endweight.")
    parser.add_argument('--rounds', nargs=1, type=int,
                        help="The number of rounds for the cipher")
    parser.add_argument('--wordsize', nargs=1, type=int,
                        help="Wordsize used for the cipher.")
    parser.add_argument('--blocksize', nargs=1, type=int,
                        help="Blocksize used for the cipher.")
    parser.add_argument('--nummessages', nargs=1, type=int,
                        help="Number of message blocks.")
    parser.add_argument('--mode', nargs=1, type=int,
                        choices=[0, 1, 2, 3, 4, 5], help=
                        "0 = search characteristic for fixed round\n"
                        "1 = search characteristic for all rounds starting at"
                        "the round specified\n"
                        "2 = search all characteristic for a specific weight\n"
                        "3 = used for key recovery\n"
                        "4 = determine the probability of the differential\n"
                        "5 = calculate best differential probability using matsui's algorithm\n")
    parser.add_argument('--timelimit', nargs=1, type=int,
                        help="Set a timelimit for the search in seconds.")
    parser.add_argument('--iterative', action="store_true",
                        help="Only search for iterative characteristics")
    parser.add_argument('--boolector', action="store_true",
                        help="Use boolector to find solutions")
    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")
    parser.add_argument('--dot', nargs=1, help="Print the trail in .dot format.")
    parser.add_argument('--latex', nargs=1, help="Print the trail in .tex format.")
    parser.add_argument('--rate', nargs=1, help="For Keccak only. Set the rate.")
    parser.add_argument('--capacity', nargs=1, help="For Keccak only. Set the capacity.")

    # Parse command line arguments and construct parameter list.
    args = parser.parse_args()
    params = loadparameters(args)

    # Check if enviroment is setup correctly.
    checkenviroment()

    # Start the solver
    startsearch(params)


if __name__ == '__main__':
    main()

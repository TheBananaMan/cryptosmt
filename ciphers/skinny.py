'''
Created on Dec 18, 2016

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class SkinnyCipher(AbstractCipher):
    """
    Represents the differential behaviour of Skinny and can be used
    to find differential characteristics for the given parameters.
    """

    name = "skinny"
    sbox = [0xc, 6, 9, 0, 1, 0xa, 2, 0xb, 3, 8, 5, 0xd, 4, 0xe, 7, 0xf]

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SC', 'SR', 'MC', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SIMON with
        the given parameters.
        """

        blocksize = parameters["blocksize"]
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if blocksize != 64:
            print("Only blocksize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Skinny w={}"
                      "rounds={}\n\n\n".format(blocksize, rounds))
            stp_file.write(header)

            # Setup variables
            sc = ["SC{}".format(i) for i in range(rounds + 1)]
            sr = ["SR{}".format(i) for i in range(rounds)]
            mc = ["MC{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sc, blocksize)
            stpcommands.setupVariables(stp_file, sr, blocksize)
            stpcommands.setupVariables(stp_file, mc, blocksize)
            stpcommands.setupVariables(stp_file, w, blocksize)

            stpcommands.setupWeightComputation(stp_file, weight, w, blocksize)

            for i in range(rounds):
                self.setupSkinnyRound(stp_file, sc[i], sr[i], mc[i], sc[i+1], 
                                      w[i], blocksize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sc, blocksize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sc[0], sc[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, blocksize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSkinnyRound(self, stp_file, sc_in, sr, mc, sc_out, w, blocksize):
        """
        Model for differential behaviour of one round Skinny
        """
        command = ""
        #Add S-box transitions
        #for i in range(16):
        #    command += self.addSbox(sc_in, sr, 4*i)

        #ShiftRows
        command += "ASSERT({0}[15:0] = {1}[15:0]);\n".format(sr, mc)

        command += "ASSERT({0}[31:20] = {1}[27:16]);\n".format(sr, mc)
        command += "ASSERT({0}[19:16] = {1}[31:28]);\n".format(sr, mc)

        command += "ASSERT({0}[39:32] = {1}[47:40]);\n".format(sr, mc)
        command += "ASSERT({0}[47:40] = {1}[39:32]);\n".format(sr, mc)

        command += "ASSERT({0}[63:60] = {1}[51:48]);\n".format(sr, mc)
        command += "ASSERT({0}[59:48] = {1}[63:52]);\n".format(sr, mc)

        #MixColumns
        command += "ASSERT("
        command += "{0}[15:0] = {1}[31:16]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[31:16], {0}[47:32]) = {1}[47:32]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[47:32], {0}[15:0]) = {1}[63:48]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[63:48], {1}[63:48]) = {1}[15:0]".format(mc, sc_out);
        command += ");\n"

        # TODO: correctly compute weight
        # For now just take the Hamming weight
        skinny_sbox = [0xc, 6, 9, 0, 1, 0xa, 2, 0xb, 3, 8, 5, 0xd, 4, 0xe, 7, 0xf]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sc_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(skinny_sbox, variables)


        stp_file.write(command)
        return

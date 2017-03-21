'''
Created on Mar 20, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl

class SPARXCipher(AbstractCipher):
    """
    Represents the differential behaviour of SPARX and can be used
    to find differential characteristics for the given parameters.
    """

    name = "sparx"
    rounds_per_step = 3

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SPARX with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% SPARX w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = left, y = right 
            x = ["X{}".format(i) for i in range(rounds + 1)]
            y = ["Y{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupSPARXRound(stp_file, x[i], y[i], x[i+1], y[i+1],
                                     w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x+y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSPARXRound(self, stp_file, x_in, y_in, x_out, y_out, w, wordsize):
        """
        Model for differential behaviour of one step SPARX
        """
        command = ""

        for i in range(self.rounds_per_step):
            command += self.A(x_in[0:16], x_in[16:32], x_in[0:16], x_in[16:32])

        for i in range(self.rounds_per_step):
            command += self.A(y_in[0:16], y_in[16:32], y_in[0:16], y_in[16:32])

        command += self.L(x_in[0:16], x_in[16:32], x_in[0:16], x_in[16:32])

        #Assert(x_out = L(A^a(x_in)) xor A^a(y_in))
        command += "ASSERT(" + x_out + " = "
        command += "BVXOR(" + x_in + " , " + y_in + ")"
        command += ");\n"

        #Assert(y_out = A^a(x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        stp_file.write(command)
        return


    def A(self, x_in, y_in, x_out, y_out):
        """
        Model for the ARX box (round) function of SPARX. A^a denotes a 
        rounds of SPECKEY.
        """
        command = ""

        #Assert((x_in >>> 7) + y_in = x_out)
        command += "ASSERT("
        command += stpcommands.getStringAdd(rotr(x_in, 7, 16),
                                            y_in, x_out, 16)
        command += ");\n"

        #Assert(x_out xor (y_in <<< 2) = y_out)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, 2, 16)
        command += "));\n"

        return command

    def L(self, x_in, y_in, x_out, y_out):
        """
        Model for the L function in SPARX. L is the Feistel function and 
        is borrowed from NOEKEON.
        """
        command = ""

        # (x_in xor y_in)
        xor_x_y = "BVXOR(" + x_in + " , " + y_in + ")"
        #(x_in xor y_in) <<< 8)
        rot_x_y = rotl(xor_x_y, 8, 16)

        #Assert(x_out = x_in xor ((x_in xor y_in) <<< 8))
        command += "ASSERT(" + x_out + " = "
        command += "BVXOR(" + x_in + " , " + rot_x_y + "));\n"

        #Assert(y_out = y_in xor ((x_in xor y_in) <<< 8))
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + y_in + " , " + rot_x_y + "));\n"

        return command



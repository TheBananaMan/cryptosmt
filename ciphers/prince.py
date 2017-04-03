'''
Created on Jan 06, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class PrinceCipher(AbstractCipher):
    """
    Represents the differential behaviour of PRINCE and can be used
    to find differential characteristics for the given parameters.
    """

    name = "prince"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SB', 'SR', 'MC', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for PRINCE with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Prince w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            sb = ["SB{}".format(i) for i in range(rounds + 1)]
            sr = ["SR{}".format(i) for i in range(rounds)]
            mc = ["MC{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sb, wordsize)
            stpcommands.setupVariables(stp_file, sr, wordsize)
            stpcommands.setupVariables(stp_file, mc, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupPrinceForwardRound(stp_file, sb[i], sr[i], mc[i], sb[i+1], 
                                      w[i], wordsize)

            self.setupPrinceMiddleRound(stp_file, sb[i], sr[i], mc[i], sb[i+1], w[i], 
                                      wordsize)

            for i in range(rounds):
                self.setupPrinceBackwardRound(stp_file, sb[i], sr[i], mc[i], sb[i+1],
                                      w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sb, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sb[0], sb[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupPrinceForwardRound(self, stp_file, sb_in, sr, mc, sb_out, w, wordsize):
        """
        Model for differential behaviour of one forward round PRINCE
        """
        command = ""

        #Linear Layer
        #ShiftRows  - as in AES            
        command += "ASSERT({}[15:0] = {}[15:0]);\n".format(sr, mc)

        command += "ASSERT({}[19:16] = {}[31:28]);\n".format(sr, mc)
        command += "ASSERT({}[31:19] = {}[27:16]);\n".format(sr, mc)

        command += "ASSERT({}[39:32] = {}[47:40]);\n".format(sr, mc)
        command += "ASSERT({}[47:40] = {}[39:32]);\n".format(sr, mc)

        command += "ASSERT({}[59:48] = {}[63:52]);\n".format(sr, mc)
        command += "ASSERT({}[63:59] = {}[51:48]);\n".format(sr, mc)                


        #MixColumns
        #todo

        # Substitution Layer
        prince_sbox = [0xb, 0xf, 3, 2, 0xa, 0xc, 9, 1, 6, 7, 8, 0, 0xe, 5, 0xd, 0x4]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sb_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(prince_sbox, variables)


        stp_file.write(command)
        return

    #fix me
    def setupPrinceBackwardRound(self, stp_file, sb_in, sr, mc, sb_out, w, wordsize):
        """
        Model for differential behaviour of one backward round PRINCE
        """
        command = ""

        #Linear Layer
        #ShiftRows - as in AES - but reverse direction            
        command += "ASSERT({}[15:0] = {}[15:0]);\n".format(sr, mc)

        command += "ASSERT({}[27:16] = {}[31:20]);\n".format(sr, mc)
        command += "ASSERT({}[31:28] = {}[19:16]);\n".format(sr, mc)

        command += "ASSERT({}[39:32] = {}[47:40]);\n".format(sr, mc)
        command += "ASSERT({}[47:40] = {}[39:32]);\n".format(sr, mc)

        command += "ASSERT({}[51:48] = {}[63:60]);\n".format(sr, mc)
        command += "ASSERT({}[63:52] = {}[59:48]);\n".format(sr, mc)                


        #MixColumns
        #todo

        # Substitution Layer
        prince_sbox = [0xb, 0xf, 3, 2, 0xa, 0xc, 9, 1, 6, 7, 8, 0, 0xe, 5, 0xd, 0x4]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sb_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(prince_sbox, variables)


        stp_file.write(command)
        return

    def setupPrinceMiddleRound(self, stp_file, sb_in, sr, mc, sb_out, w, wordsize):
        """
        Model for differential behaviour of the middle round  of PRINCE
        """
        command = ""

        # Substitution Layer
        prince_sbox = [0xb, 0xf, 3, 2, 0xa, 0xc, 9, 1, 6, 7, 8, 0, 0xe, 5, 0xd, 0x4]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sb_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(prince_sbox, variables)

                    #Linear Layer
        #ShiftRows               
        #todo

        #MixColumns
        #todo

        # Substitution Layer
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sb_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(prince_sbox, variables)


        stp_file.write(command)
        return
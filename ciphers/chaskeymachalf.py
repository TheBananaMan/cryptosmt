'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class ChasKeyMacHalf(AbstractCipher):
    """
    This class provides a model for the differential behaviour of the
    Chaskey MAC by Nicky Mouha, Bart Mennink, Anthony Van Herrewege, 
    Dai Watanabe, Bart Preneel and Ingrid Verbauwhede.
    
    For more information on Chaskey see http://mouha.be/chaskey/
    """

    name = "chaskeyhalf"
    num_messages = 1
    rot_v0_up = 5#16
    rot_v0_down = 5#16
    rot_v1_up = 15#5
    rot_v1_down = 15#7
    rot_v3_up = 8#8
    rot_v3_down = 8#13

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['v0', 'v1', 'v2', 'v3', 'w0', 'w1', 'weight']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for ChasKey
        with the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        self.num_messages = parameters["nummessages"]

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_v0_up = parameters["rotationconstants"][0]
            self.rot_v0_down = parameters["rotationconstants"][1]
            self.rot_v1_up = parameters["rotationconstants"][2]
            self.rot_v1_down = parameters["rotationconstants"][3]
            self.rot_v3_up = parameters["rotationconstants"][4]
            self.rot_v3_down = parameters["rotationconstants"][5]


        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% ChasKeyMac w={} rounds={}"
                           "\n\n\n".format(wordsize, rounds))

            # Setup variables
            # state = v0, v1, v2, v3
            # intermediate values = a0, a1, a2, a3
            v0 = ["v0{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v1 = ["v1{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v2 = ["v2{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v3 = ["v3{}".format(i) for i in range((rounds + 1) * self.num_messages)]

            # w = weight of each modular addition
            w0 = ["w0{}".format(i) for i in range(rounds * self.num_messages)]
            w1 = ["w1{}".format(i) for i in range(rounds * self.num_messages)]

            stpcommands.setupVariables(stp_file, v0, wordsize)
            stpcommands.setupVariables(stp_file, v1, wordsize)
            stpcommands.setupVariables(stp_file, v2, wordsize)
            stpcommands.setupVariables(stp_file, v3, wordsize)
            stpcommands.setupVariables(stp_file, w0, wordsize)
            stpcommands.setupVariables(stp_file, w1, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w0 + w1, wordsize, 1)

            #Minimize Weight in middle rounds
            #stpcommands.limitWeight(stp_file, 10, w0[2:4] + w1[2:4], wordsize, 1)

            for i in range(rounds):
                self.setupChasKeyRound(stp_file, i, v0[i], v1[i], v2[i], v3[i],
                                       v0[i + 1], v1[i + 1], v2[i + 1], v3[i + 1],
                                       w0[i], w1[i], wordsize)

            # Message Collision
            stpcommands.assertNonZero(stp_file, v0 + v1 + v2 + v3, wordsize)
            # zeroString = "0hex" + "0"*(wordsize / 4)
            # stpcommands.assertVariableValue(stp_file, v0[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v1[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v2[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v3[rounds], zeroString)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupChasKeyRound(self, stp_file, rnd, v0_in, v1_in, v2_in, v3_in, v0_out,
                          v1_out, v2_out, v3_out, w0, w1, wordsize):

        """
        Half a round of ChasKey

        a0 = (v1 + v0) <<< 32
        a1 = (v1 + v0) ^ (v1 <<< 13)
        a2 = (v2 + v3)
        a3 = (v2 + v3) ^ (v3 <<< 16)
        """
        command = ""

        if (rnd % 2) == 0:
            rot_one = self.rot_v1_up
            rot_two = self.rot_v3_up
            rot_three = self.rot_v0_up
        else:
            rot_one = self.rot_v1_down
            rot_two = self.rot_v3_down
            rot_three = self.rot_v0_down

        #Assert intermediate values
        #Rotate right to get correct output value

        #v0_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(v2_in, v3_in, v0_out, wordsize)
        command += ");\n"

        #v1_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v1_out, rotl(v1_in, rot_one, wordsize), rotr(v2_out, rot_three, wordsize))

        #v2_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(
            v1_in, v0_in, rotr(v2_out, rot_three, wordsize), wordsize)
        command += ");\n"

        #v3_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v3_out, rotl(v3_in, rot_two, wordsize), v0_out)

        # Compute Weights for modular addition
        # Lipmaa and Moriai

        command += "ASSERT({0} = ~".format(w0)
        command += stpcommands.getStringEq(
            v1_in, v0_in, rotr(v2_out, rot_three, wordsize))
        command += ");\n"

        command += "ASSERT({0} = ~".format(w1)
        command += stpcommands.getStringEq(v2_in, v3_in, v0_out)
        command += ");\n"

        stp_file.write(command)
        return

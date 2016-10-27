'''
Created on Oct 26, 2016

@author: ralph ankele (ralph.ankele.2015@live.rhul.ac.uk)
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class SkinnyCipher(AbstractCipher):
    """
    Represents the differential behaviour of SKINNY and can be used
    to find differential characteristics for the given parameters.
    """

    name = "skinny"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 's_sc', 's_art', 's_sr', 's_mc', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SKINNY with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        blocksize = 64  # default value
        if wordsize == 4:
            blocksize = 64
        elif wordsize == 8:
            blocksize = 128

        tweaksize = 64  # TODO: support arbitray sizes
        if "tweaksize" in parameters:
            tweaksize = parameters["tweaksize"]

        #TODO assert if tweaksize is wrong

        numberofcells = 16

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Skinny wordsize={} "
                           "tweaksize={} round={}\n\n\n".format(wordsize, 
                                                                tweaksize,
                                                                rounds))

        # Setup variables
        # 16 x wordsize state = 64/128 bit
        x = ["x{}{}".format(x,i) for i in range(rounds) 
            for x in range(numberofcells)]

        # Output after SubCells
        s_sc = ["s_sc{}{}".format(x,i) for i in range(rounds) 
            for x in range(numberofcells)]  

        # Output after AddRoundTweakey
        s_art = ["s_art{}{}".format(x,i) for i in range(rounds) 
            for x in range(numberofcells)]     

        # Output after ShiftRows
        s_sr = ["s_sr{}{}".format(x,i) for i in range(rounds) 
            for x in range(numberofcells)]  

        # Output after MixColumns
        s_mc = ["s_mc{}{}".format(x,i) for i in range(rounds) 
            for x in range(numberofcells)]   

        # w = weight
        w = ["w{}".format(i) for i in range(rounds)]        


        stpcommands.setupVariables(stp_file, x, wordsize)
        stpcommands.setupVariables(stp_file, s_sc, wordsize)
        stpcommands.setupVariables(stp_file, s_art, wordsize)
        stpcommands.setupVariables(stp_file, s_sr, wordsize)
        stpcommands.setupVariables(stp_file, s_mc, wordsize)  
        stpcommands.setupVariables(stp_file, w, wordsize)

        stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

        # No all zero characteristic
        stpcommands.assertNonZero(stp_file, x, wordsize)

        # Iterate over several rounds
        for rnd in range(rounds):
            self.setupSkinnyRound()

        stpcommands.setupQuery(stp_file)

        return

    def setupSkinnyRound(self, stp_file, x_in, y_in, x_out, y_out, and_out, w,
                        wordsize):
        """
        Model for differential behaviour of one round SKINNY
        """

        #TODO

        return


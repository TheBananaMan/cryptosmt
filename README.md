CryptoSMT
=========

CryptoSMT is an easy to use tool for cryptanalysis of symmetric primitives likes 
block ciphers or hash functions. It is based on SMT/SAT solvers like STP, Boolector, 
CryptoMiniSat and provides a simple framework to use them for cryptanalytic techniques.

Some of the features are:
* Proof properties regarding the differential behavious of a primitive.
* Find the best linear/differential characteristics.
* Compute probability of a differential.
* Find preimages for hash functions.
* Recover a secret key.

Supported Primitives
----------

The following primitives are supported by CryptoSMT at the moment: 

###### Block Ciphers
* Simon[2], 
* Speck[2], 
* Skinny[3],
* Present[4],
* Midori[5],
* LBlock[6],
* Sparx[7],
* Twine[8],
* Noekeon[9],
* Prince[10],
* Mantis[3],
* Speckey[7],
* Rectangle[11],
* Cham[12]

###### Hash Functions
* Keccak[13]

###### Stream Ciphers
* Salsa[14], 
* ChaCha[15]

###### Authenticated Encryption Ciphers
* Ketje[16], 
* Ascon[17]

###### Message Authentication Codes
* Chaskey[18], 
* SipHash[19]

Please note that at the moment not all features are available for all ciphers. A
detailed description on the application of this tool on the SIMON block ciphers and
how a differential/linear model for SIMON can be constructed is given in [1].

Installation & Tutorial
----------

For information on how to install CryptoSMT and a tutorial on how to use it see 
the [project website](http://www2.compute.dtu.dk/~stek/cryptosmt.html).

References
----------

+ [1] [Observations on the SIMON block cipher family](http://eprint.iacr.org/2015/145)
+ [2] [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404)
+ [3] [The SKINNY Family of Block Ciphers and its Low-Latency Variant MANTIS](https://eprint.iacr.org/2016/660)
+ [4] [PRESENT: An Ultra-Lightweight Block Cipher](https://link.springer.com/chapter/10.1007/978-3-540-74735-2_31)
+ [5] [Midori: A Block Cipher for Low Energy (Extended Version)](https://eprint.iacr.org/2015/1142)
+ [6] [LBlock: A Lightweight Block Cipher](https://link.springer.com/chapter/10.1007/978-3-642-21554-4_19)
+ [7] [Design Strategies for ARX with Provable Bounds: SPARX and LAX (Full Version)](https://eprint.iacr.org/2016/984)
+ [8] [TWINE: A Lightweight Block Cipher for Multiple Platforms](https://pdfs.semanticscholar.org/26b9/d188fc506fb34247c57dc365547f961576d7.pdf)
+ [9] [Nessie Proposal: NOEKEON](http://gro.noekeon.org/Noekeon-spec.pdf)
+ [10] [PRINCE - A Low-latency Block Cipher for Pervasive Computing Applications (Full version)](https://eprint.iacr.org/2012/529)
+ [11] [RECTANGLE: A Bit-slice Lightweight Block Cipher Suitable for Multiple Platforms](https://eprint.iacr.org/2014/084)
+ [12] [CHAM: A Family of Lightweight Block Ciphers for Resource-Constrained Devices](https://link.springer.com/chapter/10.1007/978-3-319-78556-1_1)
+ [13] [The Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf)
+ [14] [The Salsa20 family of stream ciphers](https://cr.yp.to/snuffle/salsafamily-20071225.pdf)
+ [15] [ChaCha, a variant of Salsa20](https://cr.yp.to/chacha/chacha-20080128.pdf)
+ [16] [CAESAR submission: Kђѡїђ v2](https://competitions.cr.yp.to/round3/ketjev2.pdf)
+ [17] [Ascon v1.2 Submission to the CAESAR Competition](https://competitions.cr.yp.to/round3/asconv12.pdf)
+ [18] [Chaskey: An Efficient MAC Algorithm for 32-bit Microcontrollers](https://eprint.iacr.org/2014/386)
+ [19] [SipHash: a fast short-input PRF](https://131002.net/siphash/siphash.pdf)

BibTex
----------
```
@misc{CryptoSMT-ref,
    author = {{Stefan Kölbl}},
    title = {{CryptoSMT: An easy to use tool for cryptanalysis of symmetric primitives}},
    note = {\url{https://github.com/kste/cryptosmt}},
}
```

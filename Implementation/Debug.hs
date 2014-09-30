module Implementation.Debug where

import AlgorithmTypes
import qualified SuiteB

implementation = (SuiteB.unimplemented "debug mode")
	{ SuiteB.aes = return (Right aes)
	}

aes = Cipher
	{ _encrypt = \k t -> putStr "Encrypting " >> print (k, t) >> return (Left "AES encryption not supported in debug mode")
	, _decrypt = \k t -> putStr "Decrypting " >> print (k, t) >> return (Left "AES decryption not supported in debug mode")
	}

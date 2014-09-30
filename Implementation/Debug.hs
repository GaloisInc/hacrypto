module Implementation.Debug (implementation) where

import AlgorithmTypes
import SuiteB

implementation = (unimplemented "debug mode")
	{ aes = return . Right $ Cipher
		{ encrypt = \k t -> putStr "Encrypting " >> print (k, t) >> return (Left "AES encryption not supported in debug mode")
		, decrypt = \k t -> putStr "Decrypting " >> print (k, t) >> return (Left "AES decryption not supported in debug mode")
		}
	}

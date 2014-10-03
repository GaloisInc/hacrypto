module Implementation.Debug (implementation) where

import Computation
import SuiteB

implementation = (unimplemented "debug mode")
	{ aes = return Cipher
		{ encrypt = \k t -> liftIO (putStr "Encrypting " >> print (k, t)) >> throwError "AES encryption not supported in debug mode"
		, decrypt = \k t -> liftIO (putStr "Decrypting " >> print (k, t)) >> throwError "AES decryption not supported in debug mode"
		}
	}

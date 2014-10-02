module Implementation.Debug (implementation) where

import AlgorithmTypes
import Control.Monad.Trans
import SuiteB
import Types

implementation = (unimplemented "debug mode")
	{ aes = return Cipher
		{ encrypt = \k t -> liftIO (putStr "Encrypting " >> print (k, t)) >> throwE "AES encryption not supported in debug mode"
		, decrypt = \k t -> liftIO (putStr "Decrypting " >> print (k, t)) >> throwE "AES decryption not supported in debug mode"
		}
	}

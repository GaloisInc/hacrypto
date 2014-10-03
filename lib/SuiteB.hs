module SuiteB (SuiteB(..), unimplemented, module AlgorithmTypes) where

import AlgorithmTypes
import Computation

data SuiteB = SuiteB
	{ aes :: Computation IO Cipher
	}

unimplemented :: String -> SuiteB
unimplemented libraryName = SuiteB
	{ aes = notImplemented "AES"
	} where
	notImplemented algorithm = throwError (algorithm ++ " not supported by " ++ libraryName)

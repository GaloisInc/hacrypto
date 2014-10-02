module SuiteB (SuiteB(..), unimplemented) where

import AlgorithmTypes
import Types

data SuiteB = SuiteB
	{ aes :: Computation IO Cipher
	}

unimplemented :: String -> SuiteB
unimplemented libraryName = SuiteB
	{ aes = notImplemented "AES"
	} where
	notImplemented algorithm = return (Left (algorithm ++ " not supported by " ++ libraryName))

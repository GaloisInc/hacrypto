{-# LANGUAGE FlexibleInstances #-}
module SuiteB
	( CipherAlgorithm(..)
	, HashAlgorithm(..)
	, Mode(..), usesIV
	, SuiteB(..)
	, replicateError, unimplemented, unimplemented_
	, module AlgorithmTypes
	) where

import AlgorithmTypes
import Computation

data CipherAlgorithm = AES
	deriving (Bounded, Enum, Eq, Ord, Read, Show)
data HashAlgorithm = SHA1
	deriving (Bounded, Enum, Eq, Ord, Read, Show)
data Mode = CBC | CFB1 | CFB8 | CFB128 | ECB | OFB
	deriving (Bounded, Enum, Eq, Ord, Read, Show)

usesIV ECB = False
usesIV _   = True

-- initialization is not permitted to fail; if something goes wrong, report it
-- when somebody tries to invoke one of the fields of 'Cipher' or 'Hash'
data SuiteB = SuiteB
	{ cipherAlg :: CipherAlgorithm -> Mode -> IO Cipher
	,   hashAlg ::   HashAlgorithm         -> IO Hash
	}

class ReplicateError a where replicateError :: Computation IO a -> IO a

instance ReplicateError Cipher where
	replicateError m = do
		v_ <- runComputation m
		case v_ of
			Right v -> return v
			Left  e -> return $ cipher
				(\_ _ _ -> throwError ("Error while initializing cipher: " ++ e))
				(\_ _ _ -> throwError ("Error while initializing cipher: " ++ e))

instance ReplicateError Hash where
	replicateError m = do
		v_ <- runComputation m
		case v_ of
			Right v -> return v
			Left  e -> return $ Hash
				{ update   = \_ -> throwError ("Error while initializing hash: " ++ e)
				, finalize =       throwError ("Error while initializing hash: " ++ e)
				, hash     = \_ -> throwError ("Error while initializing hash: " ++ e)
				}

class Unimplemented a where
	unimplemented :: String -> String -> a

unimplemented_ :: Unimplemented a => String -> a
unimplemented_ = unimplemented ""

instance Monad m => Unimplemented (Computation m a) where
	unimplemented operation libraryName = throwError (operation ++ " not supported by " ++ libraryName)

instance (Show a, Unimplemented b) => Unimplemented (a -> b) where
	unimplemented op lib a = unimplemented (show a ++ ['-' | not (null op)] ++ op) lib

instance Unimplemented a => Unimplemented (IO a) where
	unimplemented = (return .) . unimplemented

instance Unimplemented Cipher where
	unimplemented op lib = cipher
		(\_ _ _ -> unimplemented ("Encrypting with " ++ op) lib)
		(\_ _ _ -> unimplemented ("Decrypting with " ++ op) lib)

instance Unimplemented Hash where
	unimplemented op lib = Hash
		{ update   = \_ -> unimplemented (    "Updating with " ++ op) lib
		, finalize =       unimplemented ("Finalization with " ++ op) lib
		, hash     = \_ -> unimplemented (     "Hashing with " ++ op) lib
		}

instance Unimplemented SuiteB where
	unimplemented _ lib = SuiteB
		{ cipherAlg = unimplemented_ lib
		,   hashAlg = unimplemented_ lib
		}

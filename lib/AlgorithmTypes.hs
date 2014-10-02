{-# LANGUAGE NoMonomorphismRestriction #-}
module AlgorithmTypes where

import Control.Monad.Reader
import Data.ByteString (ByteString)
import Types

type Key        = ByteString
type Ciphertext = ByteString
type Plaintext  = ByteString
type Digest     = ByteString

data Cipher = Cipher
	{ encrypt :: Key -> Plaintext  -> Computation IO Ciphertext
	, decrypt :: Key -> Ciphertext -> Computation IO Plaintext
	}

data Hash = Hash
	{ update   :: Plaintext -> Computation IO ()
	, finalize ::              Computation IO Digest
	, hash     :: Plaintext -> Computation IO Digest
	}

ask0 fSelector       = join . asks $ \v -> liftIO $ fSelector v
ask1 fSelector i1    = join . asks $ \v -> liftIO $ fSelector v i1
ask2 fSelector i1 i2 = join . asks $ \v -> liftIO $ fSelector v i1 i2

callEncrypt  = ask2 encrypt
callDecrypt  = ask2 decrypt
callUpdate   = ask1 update
callFinalize = ask0 finalize
callHash     = ask1 hash

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
	{ _encrypt :: Key -> Plaintext  -> Computation IO Ciphertext
	, _decrypt :: Key -> Ciphertext -> Computation IO Plaintext
	}

data Hash = Hash
	{ _update   :: Plaintext -> Computation IO ()
	, _finalize ::              Computation IO Digest
	, _hash     :: Plaintext -> Computation IO Digest
	}

ask0 fSelector       = join . asks $ \v -> liftIO $ fSelector v
ask1 fSelector i1    = join . asks $ \v -> liftIO $ fSelector v i1
ask2 fSelector i1 i2 = join . asks $ \v -> liftIO $ fSelector v i1 i2

encrypt  = ask2 _encrypt
decrypt  = ask2 _decrypt
update   = ask1 _update
finalize = ask0 _finalize
hash     = ask1 _hash

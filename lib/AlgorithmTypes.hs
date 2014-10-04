{-# LANGUAGE NoMonomorphismRestriction #-}
module AlgorithmTypes
	( Key, IV, Ciphertext, Plaintext, Digest
	, Cipher(..), Hash(..)
	, cipher
	) where

import Computation
import Control.Applicative

type Key        = ByteString
type IV         = ByteString
type Ciphertext = ByteString
type Plaintext  = ByteString
type Digest     = ByteString

data Cipher = Cipher
	{ encrypt  :: Key -> IV -> Plaintext  -> Computation IO (IV, Ciphertext)
	, decrypt  :: Key -> IV -> Ciphertext -> Computation IO (IV, Plaintext )
	, encrypt_ :: Key -> IV -> Plaintext  -> Computation IO Ciphertext
	, decrypt_ :: Key -> IV -> Ciphertext -> Computation IO Plaintext
	}

-- for speed, we allow 'Cipher's to have separate functions that don't return
-- their 'IV' and so require less marshalling; for convenience, we allow
-- implementors to choose to ignore this possible performance boost by only
-- writing 'encrypt' and 'decrypt' and providing default 'encrypt_' and
-- 'decrypt_' operations with 'cipher'
cipher e d = Cipher
	{ encrypt  = e
	, decrypt  = d
	, encrypt_ = \key iv pt -> snd <$> e key iv pt
	, decrypt_ = \key iv ct -> snd <$> d key iv ct
	}

data Hash = Hash
	{ update   :: Plaintext -> Computation IO ()
	, finalize ::              Computation IO Digest
	, hash     :: Plaintext -> Computation IO Digest
	}

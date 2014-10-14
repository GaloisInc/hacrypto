{-# LANGUAGE FlexibleContexts, TypeFamilies #-}
module SuiteB
	( CipherAlgorithm(..)
	, HashAlgorithm(..)
	, Mode(..), usesIV
	, SuiteB, SuiteB_(..)
	, Unimplemented(..), UnimplementedArg(..), unimplemented
	, module AlgorithmTypes
	) where

import AlgorithmTypes
import Computation
import Data.List (intercalate)
import Glue

import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.RWS
import Control.Monad.State.Lazy   as Lazy
import Control.Monad.State.Strict as Strict
import Control.Monad.Trans.Identity
import Control.Monad.Trans.Maybe
import Control.Monad.Writer

data CipherAlgorithm = AES
	deriving (Bounded, Enum, Eq, Ord, Read, Show)
data HashAlgorithm = SHA1
	deriving (Bounded, Enum, Eq, Ord, Read, Show)
data Mode = CBC | CFB1 | CFB8 | CFB128 | ECB | OFB
	deriving (Bounded, Enum, Eq, Ord, Read, Show)

usesIV ECB = False
usesIV _   = True

data SuiteB_ m m' = SuiteB
	{ cipherAlg :: CipherAlgorithm -> Mode -> m (Cipher m')
	,   hashAlg ::   HashAlgorithm         -> m (Hash   m')
	}
type SuiteB m = SuiteB_ m m

class Unimplemented a where
	unimplemented_ :: ([String] -> String) -> String -> a

-- the two basic instances: String and (arg1 -> arg2 -> ... -> String)
instance a ~ Char => Unimplemented [a] where
	unimplemented_ f lib = unwords [f [], "not supported by", lib]

instance (UnimplementedArg a, Unimplemented b) => Unimplemented (a -> b) where
	unimplemented_ f lib op = unimplemented_ (\ops -> f (showArg op:ops)) lib

-- MonadError instances
instance (Monad m, e ~ String)           => Unimplemented (      ExceptT e     m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)
instance  Unimplemented (m a)            => Unimplemented (    IdentityT       m a) where unimplemented_ f lib = IdentityT  (unimplemented_ f lib)
instance (Unimplemented (m a), Monad m)  => Unimplemented (       MaybeT       m a) where unimplemented_ f lib = lift       (unimplemented_ f lib)
instance  MonadError String m            => Unimplemented (      ReaderT r     m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)
instance (MonadError String m, Monoid w) => Unimplemented (         RWST r w s m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)
instance  MonadError String m            => Unimplemented (Strict.StateT     s m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)
instance  MonadError String m            => Unimplemented (  Lazy.StateT     s m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)
instance (MonadError String m, Monoid w) => Unimplemented (      WriterT   w   m a) where unimplemented_ f lib = throwError (unimplemented_ f lib)

class UnimplementedArg a where showArg :: a -> String
instance a ~ Char => UnimplementedArg [a] where showArg = id
instance UnimplementedArg CipherAlgorithm where showArg = show
instance UnimplementedArg   HashAlgorithm where showArg = show
instance UnimplementedArg Mode            where showArg = show

unimplemented :: Unimplemented a => String -> a
unimplemented = unimplemented_ $ \xs -> case xs of
	[] -> "<unknown operation>"
	_  -> intercalate "-" xs

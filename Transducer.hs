{-# LANGUAGE LambdaCase, TypeOperators #-}
module Transducer
	( module Glue
	, module Transducer
	, module Types
	) where

import Control.Monad.Writer
import Control.Monad.Trans.Maybe
import Data.Maybe
import Data.Traversable
import Glue
import Text.Regex.Applicative
import Text.Regex.Applicative.Reference
import Types

-- TODO: switch "reference" back to "match" everywhere once we clear up
-- https://github.com/feuerbach/regex-applicative/issues/19

type Transducer_  i o = RE i `Compose` WriterT o IO
type Transducer     t = Transducer_ t [t]
type Transformer_ i o = i -> MaybeT IO o
type Transformer    t = Transformer_ t t

type Computation t = IO (Either String t)
type Producer    t = WriterT [t] IO ()

-- TODO: move this into regex-applicative to avoid recomputing f
maybeSym :: (s -> Maybe a) -> RE s a
maybeSym f = fromJust . f <$> psym (isJust . f)

transSym :: (a -> Maybe b) -> Transducer a b
transSym f = Compose (maybeSym f') where
	f' a = (\b -> tell [a] >> return b) <$> f a

-- TODO: check for ambiguity at every call to "match"/"reference"
vectors :: Transducer String a -> (a -> Transducer Block b) -> Transformer Vectors
vectors transHead fTransBlock Vectors { header = h, blocks = bs } = do
	(a, h' ) <- runTransducer transHead h
	(_, bs') <- runTransducer (fTransBlock a) bs
	return Vectors { header = h', blocks = bs' }

anyHeader :: Transducer Block a -> Transformer Vectors
anyHeader trans = vectors (many (transSym return)) (const trans)

block :: Bool -> Transducer Equation a -> Transducer Block a
block bRequest = Compose . go . getCompose where
	go pEqs = maybeSym $ unwrap >=> reference pEqs >=> return . onOutput wrap

	wrap   :: [Equation] -> [Block]
	unwrap :: Block -> Maybe [Equation]

	wrap newEqs = [Block { bracketed = bRequest, equations = newEqs}]
	unwrap Block { bracketed = bActual, equations = eqs }
		= guard (bRequest == bActual) >> return eqs

parameters :: Transducer Equation a -> Transducer Block a
tests      :: Transducer Equation a -> Transducer Block a
parameters = block True
tests      = block False

equation :: (Value -> Maybe a) -> String -> Transducer Equation a
equation extract lRequest = transSym $ \Equation { label = lActual, value = v } -> do
	guard (lRequest == lActual)
	extract v

-- TODO: probably a lot of this could be cleaner with lenses
int  :: String -> Transducer Equation Integer
hex  :: String -> Transducer Equation ByteString
flag :: String -> Transducer Equation ()

int = equation $ \case
	Basic { decimal = v } -> v
	_ -> Nothing

hex = equation $ \case
	Basic { hexadecimal = v } -> v
	_ -> Nothing

flag = equation $ \case
	Flag -> Just ()
	_    -> Nothing

emit :: (a -> Value) -> String -> Computation a              -> Producer Equation
emitInt    ::           String -> Computation Integer        -> Producer Equation
emitHex    ::           String -> Computation ByteString     -> Producer Equation
emitBool   ::           String -> Computation Bool           -> Producer Equation
emitReport ::           String -> Computation (Bool, String) -> Producer Equation

emit f l io = do
	v <- liftIO io
	tell [Equation { label = l, value = case v of
		Left  e -> ErrorMessage e
		Right a -> f a
		}]

emitInt    = emit basicDec
emitHex    = emit basicHex
emitBool   = emit Boolean
emitReport = emit (uncurry SuccessReport)

runTransducer  :: Transducer t a -> Transformer_ [t] (a, [t])
execTransducer :: Transducer t a -> Transformer  [t]
evalTransducer :: Transducer t a -> Transformer_ [t]  a

runTransducer (Compose trans) = MaybeT . traverse runWriterT . reference trans
execTransducer trans input = snd <$> runTransducer trans input
evalTransducer trans input = fst <$> runTransducer trans input

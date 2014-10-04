{-# LANGUAGE ConstraintKinds, LambdaCase, TypeOperators #-}
module Transducer
	( module Glue
	, module Transducer
	, module Types
	) where

import Control.Monad.Reader
import Control.Monad.Trans.Maybe
import Control.Monad.Writer
import Computation
import Data.Maybe
import Data.Traversable
import Glue
import Text.Regex.Applicative
import Text.Regex.Applicative.Reference
import Types

-- TODO: switch "reference" back to "match" everywhere once we clear up
-- https://github.com/feuerbach/regex-applicative/issues/19
-- update: see transformers.dpatch for the fix to the transformers package that
-- makes "match" terminate

type Transducer_  m i o = RE i `Compose` WriterT o m
type Transformer_ m i o = i -> Computation m o
type Transducer   m   t = Transducer_  m t [t]
type Transformer  m   t = Transformer_ m t  t
type Producer     m   t = WriterT [t] m ()

type Monad' m = (Applicative m, Monad m)

-- TODO: move this into regex-applicative to avoid recomputing f
maybeSym :: (s -> Maybe a) -> RE s a
maybeSym f = fromJust . f <$> psym (isJust . f)

transSym :: Monad' m => (a -> Maybe b) -> Transducer m a b
transSym f = Compose (maybeSym f') where
	f' a = (\b -> tell [a] >> return b) <$> f a

-- TODO: check for ambiguity at every call to "match"/"reference"
-- TODO: give some basic building blocks for parsing headers
vectors :: Monad' m => Transducer m String a -> (a -> Transducer m Block b) -> Transformer m Vectors
vectors transHead fTransBlock Vectors { headers = h, blocks = bs } = do
	(a, h' ) <- runTransducer transHead h
	(_, bs') <- runTransducer (fTransBlock a) bs
	return Vectors { headers = h', blocks = bs' }

anyHeader :: Monad' m => Transducer m Block a -> Transformer m Vectors
anyHeader trans = vectors (many transAny) (const trans)

header :: Monad' m => Transducer m Char a -> Transducer m String a
header = Compose . go . getCompose where
	go pChars = maybeSym $ reference pChars >=> return . onOutput return

-- TODO: this "trans" prefix is a symptom of not using the module system
-- properly
transString :: (Monad m, Eq a) => [a] -> Transducer m a ()
transString s = Compose $ tell s <$ string s

transAny :: Monad' m => Transducer m a a
transAny = transSym return

block :: Monad' m => Bool -> Transducer m Equation a -> Transducer m Block a
block bRequest = Compose . go . getCompose where
	go pEqs = maybeSym $ unwrap >=> reference pEqs >=> return . onOutput wrap

	wrap   :: [Equation] -> [Block]
	unwrap :: Block -> Maybe [Equation]

	wrap newEqs = [Block { bracketed = bRequest, equations = newEqs}]
	unwrap Block { bracketed = bActual, equations = eqs }
		= guard (bRequest == bActual) >> return eqs

parameters :: Monad' m => Transducer m Equation a -> Transducer m Block a
tests      :: Monad' m => Transducer m Equation a -> Transducer m Block a
parameters = block True
tests      = block False

equation :: Monad' m => (Value -> Maybe a) -> String -> Transducer m Equation a
equation extract lRequest = transSym $ \Equation { label = lActual, value = v } -> do
	guard (lRequest == lActual)
	extract v

-- TODO: probably a lot of this could be cleaner with lenses
int  :: Monad' m => String -> Transducer m Equation Integer
hex  :: Monad' m => String -> Transducer m Equation ByteString
flag :: Monad' m => String -> Transducer m Equation ()

int = equation $ \case
	Basic { decimal = v } -> v
	_ -> Nothing

hex = equation $ \case
	Basic { hexadecimal = v } -> v
	_ -> Nothing

flag = equation $ \case
	Flag -> Just ()
	_    -> Nothing

emit       :: Monad' m => (a -> Value)
                       -> String -> Computation m a              -> Producer m Equation
emitInt    :: Monad' m => String -> Computation m Integer        -> Producer m Equation
emitHex    :: Monad' m => String -> Computation m ByteString     -> Producer m Equation
emitBool   :: Monad' m => String -> Computation m Bool           -> Producer m Equation
emitReport :: Monad' m => String -> Computation m (Bool, String) -> Producer m Equation

emit f l io = do
	v <- lift (runComputation io)
	tell [Equation { label = l, value = case v of
		Left  e -> ErrorMessage e
		Right a -> f a
		}]

emitInt    = emit basicDec
emitHex    = emit basicHex
emitBool   = emit Boolean
emitReport = emit (uncurry SuccessReport)

runTransducer  :: Monad' m => Transducer m t a -> Transformer_ m [t] (a, [t])
execTransducer :: Monad' m => Transducer m t a -> Transformer  m [t]
evalTransducer :: Monad' m => Transducer m t a -> Transformer_ m [t]  a

runTransducer (Compose trans) = liftMaybe "transducer failed" . traverse runWriterT . reference trans
execTransducer trans input = snd <$> runTransducer trans input
evalTransducer trans input = fst <$> runTransducer trans input

runTransformer :: Transformer_ (ReaderT r m) i o -> r -> i -> Computation m o
runTransformer f r i = computation $ runReaderT (runComputation (f i)) r

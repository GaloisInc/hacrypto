{-# LANGUAGE ConstraintKinds, LambdaCase, TypeOperators #-}
module Transducer
	( module Glue
	, module Transducer
	, module Types
	) where

import Control.Monad.Reader
import Control.Monad.Trans.Maybe
import Control.Monad.Writer
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

-- TODO: MaybeT sucks, Computation is better, some appropriate EitherT is even
-- better still

type Transducer_  m i o = RE i `Compose` WriterT o m
type Transducer   m   t = Transducer_ m t [t]
type Transformer_ m i o = i -> MaybeT m o
type Transformer  m   t = Transformer_ m t t
type Producer     m   t = WriterT [t] m ()

type MonadIO' m = (Applicative m, MonadIO m)

-- TODO: move this into regex-applicative to avoid recomputing f
maybeSym :: (s -> Maybe a) -> RE s a
maybeSym f = fromJust . f <$> psym (isJust . f)

transSym :: MonadIO' m => (a -> Maybe b) -> Transducer m a b
transSym f = Compose (maybeSym f') where
	f' a = (\b -> tell [a] >> return b) <$> f a

-- TODO: check for ambiguity at every call to "match"/"reference"
-- TODO: give some basic building blocks for parsing headers
vectors :: MonadIO' m => Transducer m String a -> (a -> Transducer m Block b) -> Transformer m Vectors
vectors transHead fTransBlock Vectors { header = h, blocks = bs } = do
	(a, h' ) <- runTransducer transHead h
	(_, bs') <- runTransducer (fTransBlock a) bs
	return Vectors { header = h', blocks = bs' }

anyHeader :: MonadIO' m => Transducer m Block a -> Transformer m Vectors
anyHeader trans = vectors (many (transSym return)) (const trans)

block :: MonadIO' m => Bool -> Transducer m Equation a -> Transducer m Block a
block bRequest = Compose . go . getCompose where
	go pEqs = maybeSym $ unwrap >=> reference pEqs >=> return . onOutput wrap

	wrap   :: [Equation] -> [Block]
	unwrap :: Block -> Maybe [Equation]

	wrap newEqs = [Block { bracketed = bRequest, equations = newEqs}]
	unwrap Block { bracketed = bActual, equations = eqs }
		= guard (bRequest == bActual) >> return eqs

parameters :: MonadIO' m => Transducer m Equation a -> Transducer m Block a
tests      :: MonadIO' m => Transducer m Equation a -> Transducer m Block a
parameters = block True
tests      = block False

equation :: MonadIO' m => (Value -> Maybe a) -> String -> Transducer m Equation a
equation extract lRequest = transSym $ \Equation { label = lActual, value = v } -> do
	guard (lRequest == lActual)
	extract v

-- TODO: probably a lot of this could be cleaner with lenses
int  :: MonadIO' m => String -> Transducer m Equation Integer
hex  :: MonadIO' m => String -> Transducer m Equation ByteString
flag :: MonadIO' m => String -> Transducer m Equation ()

int = equation $ \case
	Basic { decimal = v } -> v
	_ -> Nothing

hex = equation $ \case
	Basic { hexadecimal = v } -> v
	_ -> Nothing

flag = equation $ \case
	Flag -> Just ()
	_    -> Nothing

emit       :: MonadIO' m => (a -> Value) -> String -> Computation m a              -> Producer m Equation
emitInt    :: MonadIO' m =>                 String -> Computation m Integer        -> Producer m Equation
emitHex    :: MonadIO' m =>                 String -> Computation m ByteString     -> Producer m Equation
emitBool   :: MonadIO' m =>                 String -> Computation m Bool           -> Producer m Equation
emitReport :: MonadIO' m =>                 String -> Computation m (Bool, String) -> Producer m Equation

emit f l io = do
	v <- lift io
	tell [Equation { label = l, value = case v of
		Left  e -> ErrorMessage e
		Right a -> f a
		}]

emitInt    = emit basicDec
emitHex    = emit basicHex
emitBool   = emit Boolean
emitReport = emit (uncurry SuccessReport)

runTransducer  :: MonadIO' m => Transducer m t a -> Transformer_ m [t] (a, [t])
execTransducer :: MonadIO' m => Transducer m t a -> Transformer  m [t]
evalTransducer :: MonadIO' m => Transducer m t a -> Transformer_ m [t]  a

runTransducer (Compose trans) = MaybeT . traverse runWriterT . reference trans
execTransducer trans input = snd <$> runTransducer trans input
evalTransducer trans input = fst <$> runTransducer trans input

runTransformer :: Transformer_ (ReaderT r m) i o -> r -> i -> m (Maybe o)
runTransformer f r i = runReaderT (runMaybeT (f i)) r

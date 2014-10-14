{-# LANGUAGE ConstraintKinds, FlexibleContexts, LambdaCase, TypeOperators #-}
module Transducer
	( module Glue
	, module Transducer
	, module Types
	) where

import Control.Monad.Reader
import Control.Monad.Trans.Maybe
import Control.Monad.Writer
import Computation
import Data.Foldable
import Data.Maybe
import Data.Traversable
import Glue
import Text.Regex.Applicative hiding (anySym, string, sym)
import Text.Regex.Applicative.Reference
import Types

import qualified Text.Regex.Applicative as RE

-- TODO: switch "reference" back to "match" everywhere once we clear up
-- https://github.com/feuerbach/regex-applicative/issues/19
-- update: see transformers.dpatch for the fix to the transformers package that
-- makes "match" terminate

type Transducer_  m i o = RE i `Compose` WriterT o m
type Transformer_ m i o = i -> m o
type Transducer   m   t = Transducer_  m t [t]
type Transformer  m   t = Transformer_ m t  t

type Monad' m = (Applicative m, Monad m)

-- TODO: move this into regex-applicative to avoid recomputing f
maybeSym :: (s -> Maybe a) -> RE s a
maybeSym f = fromJust . f <$> psym (isJust . f)

sym :: Monad' m => (a -> Maybe b) -> Transducer m a b
sym f = Compose (maybeSym f') where
	f' a = (\b -> tell [a] >> return b) <$> f a

-- TODO: check for ambiguity at every call to "match"/"reference"
-- TODO: give some basic building blocks for parsing headers
vectors :: (Monad' m, MonadError String m) => Transducer m String a -> (a -> Transducer m Block b) -> Transformer m Vectors
vectors transHead fTransBlock Vectors { headers = h, blocks = bs } = do
	(a, h' ) <- runTransducer transHead h
	(_, bs') <- runTransducer (fTransBlock a) bs
	return Vectors { headers = h', blocks = bs' }

anyHeader :: (Monad' m, MonadError String m) => Transducer m Block a -> Transformer m Vectors
anyHeader trans = vectors (many anySym) (const trans)

header :: Monad' m => Transducer m Char a -> Transducer m String a
header = Compose . go . getCompose where
	go pChars = maybeSym $ reference pChars >=> return . onOutput return

string :: (Monad m, Eq a) => [a] -> Transducer m a ()
string s = Compose $ tell s <$ RE.string s

anySym :: Monad' m => Transducer m a a
anySym = sym return

anyVal :: (Monad' m, Bounded a, Enum a, Show a) => Transducer m Char a
anyVal = asum [m <$ string (show m) | m <- [minBound..maxBound]]

block :: Monad' m => Bool -> Transducer m Equation a -> Transducer m Block a
block bRequest = Compose . go . getCompose where
	go pEqs = maybeSym $ \block -> do
		guard (bracketed block == bRequest)
		onOutput (updateEqs block) <$> reference pEqs (equations block)

	updateEqs block newEqs = [block { equations = newEqs }]

parameters :: Monad' m => Transducer m Equation a -> Transducer m Block a
tests      :: Monad' m => Transducer m Equation a -> Transducer m Block a
parameters = block True
tests      = block False

equation :: Monad' m => (Value -> Maybe a) -> String -> Transducer m Equation a
equation extract lRequest = sym $ \Equation { label = lActual, value = v } -> do
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

type Emit m = (MonadError String m, MonadWriter [Equation] m)
emit       :: Emit m => (a -> Value)
                     -> String -> m a              -> m ()
emitInt    :: Emit m => String -> m Integer        -> m ()
emitHex    :: Emit m => String -> m ByteString     -> m ()
emitBool   :: Emit m => String -> m Bool           -> m ()
emitReport :: Emit m => String -> m (Bool, String) -> m ()

emit f l m = do
	v <- catchError (Right `liftM` m) (return . Left)
	tell [Equation { label = l, value = case v of
		Left  e -> ErrorMessage e
		Right a -> f a
		}]

emitInt    = emit basicDec
emitHex    = emit basicHex
emitBool   = emit Boolean
emitReport = emit (uncurry SuccessReport)

runTransducer  :: (Monad' m, MonadError String m) => Transducer m t a -> Transformer_ m [t] (a, [t])
execTransducer :: (Monad' m, MonadError String m) => Transducer m t a -> Transformer  m [t]
evalTransducer :: (Monad' m, MonadError String m) => Transducer m t a -> Transformer_ m [t]  a

runTransducer (Compose trans) = maybe (throwError "transducer failed") runWriterT . reference trans
execTransducer trans input = snd <$> runTransducer trans input
evalTransducer trans input = fst <$> runTransducer trans input

runTransformer :: Transformer_ (ReaderT r (Computation m)) i o -> r -> i -> Computation m o
runTransformer f r i = runReaderT (f i) r

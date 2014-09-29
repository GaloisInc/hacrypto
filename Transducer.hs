{-# LANGUAGE LambdaCase, TypeOperators #-}
module Transducer
	( module Glue
	, module Transducer
	, module Types
	) where

import Control.Monad.Writer
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
type Transformer_ i o = i -> IO (Maybe o)
type Transformer    t = Transformer_ t t

-- TODO: move this into regex-applicative to avoid recomputing f
maybeSym :: (s -> Maybe a) -> RE s a
maybeSym f = fromJust . f <$> psym (isJust . f)

transSym :: (a -> Maybe b) -> Transducer a b
transSym f = Compose (maybeSym f') where
	f' a = (\b -> tell [a] >> return b) <$> f a

-- TODO: check for ambiguity at every call to "match"/"reference"
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

eqSym :: (Value -> Maybe a) -> String -> Transducer Equation a
eqSym extract lRequest = transSym $ \Equation { label = lActual, value = v } -> do
	guard (lRequest == lActual)
	extract v

-- TODO: probably a lot of this could be cleaner with lenses
flag :: String -> Transducer Equation ()
int  :: String -> Transducer Equation Integer
hex  :: String -> Transducer Equation ByteString

flag = eqSym $ \case
	Flag -> Just ()
	_    -> Nothing

int = eqSym $ \case
	Basic { decimal = v } -> v
	_ -> Nothing

hex = eqSym $ \case
	Basic { hexadecimal = v } -> v
	_ -> Nothing

emitHex :: String -> IO ByteString -> WriterT [Equation] IO ()
emitHex l hexIO = do
	hex <- liftIO hexIO
	tell [Equation { label = l, value = basicHex hex }]

anyHeader :: Transducer Block a -> Transformer Vectors
anyHeader (Compose transBlock) Vectors { header = h, blocks = bs } =
	case reference transBlock bs of
		Nothing -> return Nothing
		Just m  -> do
			(_, bs') <- runWriterT m
			return (Just Vectors { header = h, blocks = bs' })

runTransducer :: Transducer t a -> [t] -> IO (Maybe (a, [t]))
runTransducer (Compose trans) = traverse runWriterT . reference trans

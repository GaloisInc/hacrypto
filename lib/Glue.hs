{-# LANGUAGE TypeFamilies #-}
module Glue
	( module Control.Applicative
	, module Data.Functor.Compose
	, module Glue
	) where

import Data.ByteString
import Data.Default
import Control.Monad.Writer
import Control.Applicative
import Data.Functor.Compose

instance Default ByteString where def = pack []

onOutput :: Functor f => (o -> o') -> WriterT o f a -> WriterT o' f a
onOutput f = mapWriterT ((\(a, o) -> (a, f o)) <$>)

-- TODO: is this really the best abstraction Haskell can offer here?
-- "fm ~ Compose f m" just introduces an abbreviation "fm"
do0 :: (Monad m, Applicative f, fm ~ Compose f m) =>                                                      m r  -> fm r
do1 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a ->                         (a ->                m r) -> fm r
do2 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a -> fm b ->                 (a -> b ->           m r) -> fm r
do3 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a -> fm b -> fm c ->         (a -> b -> c ->      m r) -> fm r
do4 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a -> fm b -> fm c -> fm d -> (a -> b -> c -> d -> m r) -> fm r
do0 mr = Compose (pure mr)
do1 (Compose fma) famr = Compose ((\ma -> do
	a <- ma
	famr a
	) <$> fma)
do2 (Compose fma) (Compose fmb) fabmr = Compose ((\ma mb -> do
	a <- ma
	b <- mb
	fabmr a b
	) <$> fma <*> fmb)
do3 (Compose fma) (Compose fmb) (Compose fmc) fabcmr = Compose ((\ma mb mc -> do
	a <- ma
	b <- mb
	c <- mc
	fabcmr a b c
	) <$> fma <*> fmb <*> fmc)
do4 (Compose fma) (Compose fmb) (Compose fmc) (Compose fmd) fabcdmr = Compose ((\ma mb mc md -> do
	a <- ma
	b <- mb
	c <- mc
	d <- md
	fabcdmr a b c d
	) <$> fma <*> fmb <*> fmc <*> fmd)

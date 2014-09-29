{-# LANGUAGE TypeFamilies #-}
module Glue
	( module Control.Applicative
	, module Data.Functor.Compose
	, module Glue
	) where

import Control.Monad.Writer
import Control.Applicative
import Data.Functor.Compose

onOutput :: (o -> o') -> WriterT o IO a -> WriterT o' IO a
onOutput f = mapWriterT ((\(a, o) -> (a, f o)) <$>)

-- TODO: is this really the best abstraction Haskell can offer here?
-- "fm ~ Compose f m" just introduces an abbreviation "fm"
do0 :: (Monad m, Applicative f, fm ~ Compose f m) =>                                         m r  -> fm r
do1 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a ->                 (a ->           m r) -> fm r
do2 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a -> fm b ->         (a -> b ->      m r) -> fm r
do3 :: (Monad m, Applicative f, fm ~ Compose f m) => fm a -> fm b -> fm c -> (a -> b -> c -> m r) -> fm r
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

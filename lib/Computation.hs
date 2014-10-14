{-# LANGUAGE FlexibleContexts #-}
module Computation
	( Computation, computation, runComputation, liftComputation
	, liftMaybe, liftMaybe_
	, MonadError(..), onError, (<?>)
	, reifyException, reifyIOException
	, Delayed, delayFailure, deliverFailure
	, MonadIO, liftIO
	, allocaBytes
	, ByteStringConversion(..), ByteString
	, CString, CStringLen, CUString, CUStringLen
	, cString, cStringLen, cuString, cuStringLen
	, inComputation, useDefAsNothing
	, unsafeArbString, unsafeArbStringLen
	) where

import Control.Applicative
import Control.Monad.Except
import Control.Monad.Trans.Maybe
import Control.Exception
import Data.ByteString (ByteString, packCString, packCStringLen, useAsCString, useAsCStringLen)
import Data.Default
import Foreign (Ptr, castPtr)
import qualified Foreign as Foreign
import Foreign.C.Types
import Foreign.C.String

type Computation = ExceptT String
computation = ExceptT
runComputation = runExceptT

liftComputation :: (MonadIO m, MonadError String m) => Computation IO a -> m a
liftComputation m = do
	v_ <- liftIO (runComputation m)
	case v_ of
		Left err -> throwError err
		Right v  -> return v

liftMaybe :: Monad m => String -> m (Maybe a) -> Computation m a
liftMaybe err m = do
	mv <- lift m
	case mv of
		Nothing -> throwError err
		Just v  -> return v

liftMaybe_ :: Monad m => m (Maybe a) -> Computation m a
liftMaybe_ = liftMaybe "(unknown error)"

onError :: Functor m => (e -> e') -> ExceptT e m a -> ExceptT e' m a
onError f = ExceptT . (either (Left . f) Right <$>) . runExceptT

infix 2 <?>
(<?>) :: Functor m => Computation m a -> String -> Computation m a
m <?> s = onError (const s) m

catchIO :: (MonadIO m, Exception e) => IO a -> (e -> m a) -> m a
catchIO io throw = join . liftIO $
	catch (return <$> io) (return . throw)

reifyException :: (MonadIO m, MonadError e' m, Exception e) => IO a -> (e -> e') -> m a
reifyException io transform = catchIO io (throwError . transform)

reifyIOException :: (MonadIO m, MonadError String m) => String -> IO a -> m a
reifyIOException prefix io = reifyException io (\e -> prefix ++ " " ++ show (e :: IOException))

type Delayed = Either String
delayFailure   :: Monad m => Computation m a -> Computation m (Delayed a)
deliverFailure :: Monad m => Delayed       a -> Computation m          a
delayFailure   = lift . runExceptT
deliverFailure = ExceptT . return

liftLocal :: ((a -> m (Either e b)) -> m' (Either e' b')) -> ((a -> ExceptT e m b) -> ExceptT e' m' b')
liftLocal f g = ExceptT (f (runExceptT . g))

allocaBytes :: Int -> (Ptr a -> Computation IO b) -> Computation IO b
allocaBytes = liftLocal . Foreign.allocaBytes

-- class ByteStringConvert m t where useAs :: ...; pack :: ...
-- (but more explicit, which ends up being less annoying anyway because the
-- type annotations necessary to use the class make it pretty explicit anyway)
data ByteStringConversion m bs t r = ByteStringConversion
	{ useAs :: bs -> (t -> m r) -> m r
	, pack  :: t -> m bs
	}

type CUString    = Ptr CUChar
type CUStringLen = (Ptr CUChar, CUInt)

cString     :: ByteStringConversion IO ByteString CString     r
cStringLen  :: ByteStringConversion IO ByteString CStringLen  r
cuString    :: ByteStringConversion IO ByteString CUString    r
cuStringLen :: ByteStringConversion IO ByteString CUStringLen r
cString     = ByteStringConversion useAsCString    packCString
cStringLen  = ByteStringConversion useAsCStringLen packCStringLen
cuString    = unsafeArbString
cuStringLen = unsafeArbStringLen

unsafeArbString    :: ByteStringConversion IO ByteString (Ptr char) r
unsafeArbStringLen :: Integral int => ByteStringConversion IO ByteString (Ptr char, int) r
unsafeArbString    = usingConversion castPtr castPtr cString
unsafeArbStringLen = usingConversion convert convert cStringLen where
	convert (str, len) = (castPtr str, fromIntegral len)

usingConversion :: (t' -> t) -> (t -> t') -> ByteStringConversion m bs t r -> ByteStringConversion m bs t' r
usingConversion to from bsc = ByteStringConversion
	{ useAs = \bs f -> useAs bsc bs (f . from)
	, pack  = pack bsc . to
	}

inComputation :: Monad m => ByteStringConversion m bs t (Either String r)
                         -> ByteStringConversion (Computation m) bs t r
inComputation bsc = ByteStringConversion
	{ useAs = liftLocal . useAs bsc
	, pack  = lift      . pack  bsc
	}

useDefAsNothing :: (Default t, Eq t, Applicative m)
                => ByteStringConversion m        bs  t r
                -> ByteStringConversion m (Maybe bs) t r
useDefAsNothing bsc = ByteStringConversion
	{ useAs = \mbs f -> case mbs of
		Nothing -> f def
		Just bs -> useAs bsc bs f
	, pack  = \t -> if t == def then pure Nothing else Just <$> pack bsc t
	}

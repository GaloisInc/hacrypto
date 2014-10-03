{-# LANGUAGE GeneralizedNewtypeDeriving, MultiParamTypeClasses #-}
module Implementation.Cryptodev (implementation) where

#include <crypto/cryptodev.h>
#include <asm-generic/ioctl.h>

import Computation
import Data.Bits
import Data.ByteString (length)
import Data.Default
import Data.Functor
import Data.Word
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable
import SuiteB
import System.Mem.Weak
import System.Posix.IO
import System.Posix.IOCtl
import System.Posix.Types

-- TODO: for now, can't cut off the CRYPTO_ prefix because the leftover bits
-- can start with 3, and can't properly rename things starting with 3 because
-- of https://github.com/haskell/c2hs/issues/113
{#enum cryptodev_crypto_op_t as OperationType {} deriving (Eq, Ord, Read, Show)#}
{#enum define Direction {COP_ENCRYPT as Encrypt, COP_DECRYPT as Decrypt} deriving (Eq, Ord, Read, Show)#}
{#enum define IOCtl
	{ CIOCGSESSION as CtlStartSession
	, CIOCFSESSION as CtlEndSession
	, CIOCCRYPT as CtlCrypt
	}#}
{#enum define CFlag
	{ COP_FLAG_UPDATE         as CUpdate
	, COP_FLAG_FINAL          as CFinal
	, COP_FLAG_WRITE_IV       as CWriteIV
	, COP_FLAG_NO_ZC          as CNoZC
	, COP_FLAG_AEAD_TLS_TYPE  as CAEADTLS
	, COP_FLAG_AEAD_SRTP_TYPE as CAEADSRTP
	, COP_FLAG_RESET          as CReset
	}#}

newtype Flag = Flag { getFlag :: Word16 } deriving (Eq, Ord, Read, Show, Bounded, Enum, Bits, Num, Real, Integral)
fUpdate, fFinal, fWriteIV, fNoZC, fAEADTLS, fAEADSRTP, fReset :: Flag
[fUpdate, fFinal, fWriteIV, fNoZC, fAEADTLS, fAEADSRTP, fReset] = fromIntegral . fromEnum <$>
	[CUpdate, CFinal, CWriteIV, CNoZC, CAEADTLS, CAEADSRTP, CReset]

data Session = Session
	{ sCipher    :: Maybe OperationType
	, sMac       :: Maybe OperationType
	, sRNG       :: Maybe OperationType
	, sKey       :: Maybe ByteString
	, sMacKey    :: Maybe ByteString
	, sSes       :: Word32
	} deriving (Eq, Ord, Show)

data Operation = Operation
	{ oSes   :: Word32
	, oOp    :: Direction
	, oFlags :: Flag
	, oLen   :: Word32
	, oSrc   :: Ptr Word8
	, oDst   :: Ptr Word8
	, oMac   :: Ptr Word8
	, oIV    :: Ptr Word8
	} deriving (Eq, Ord, Show)

instance Default (Ptr a)       where def = nullPtr
instance Default CUInt         where def = 0
instance Default Direction     where def = Encrypt
instance Default Flag          where def = 0
instance Default Session       where def = Session   def def def def def def
instance Default Operation     where def = Operation def def def def def def def def

toOperationType 0 = Nothing
toOperationType n = Just (toEnum (fromIntegral n))
fromOperationType Nothing  = 0
fromOperationType (Just o) = fromIntegral (fromEnum o)

instance Storable Session where
	sizeOf    _ = {#sizeof  session_op#}
	alignment _ = {#alignof session_op#}
	peek p = do
		vCipher    <- {#get session_op.cipher   #} p
		vMac       <- {#get session_op.mac      #} p
		vRng       <- {#get session_op.rng      #} p
		vKeylen    <- {#get session_op.keylen   #} p
		vKey       <- {#get session_op.key      #} p
		vMackeylen <- {#get session_op.mackeylen#} p
		vMackey    <- {#get session_op.mackey   #} p
		vSes       <- {#get session_op.ses      #} p
		bsKey      <- pack mcuStringLen (   vKey,    vKeylen)
		bsMacKey   <- pack mcuStringLen (vMackey, vMackeylen)
		return Session
			{ sCipher    = toOperationType vCipher
			, sMac       = toOperationType vMac
			, sRNG       = toOperationType vRng
			, sKey       = bsKey
			, sMacKey    = bsMacKey
			, sSes       = fromIntegral vSes
			}
	poke p v = useAs mcuStringLen (sKey    v) $ \(   keyPtr,    keyLen) ->
	           useAs mcuStringLen (sMacKey v) $ \(mackeyPtr, mackeyLen) -> do
		{#set session_op.cipher   #} p (fromOperationType $ sCipher    v)
		{#set session_op.mac      #} p (fromOperationType $ sMac       v)
		{#set session_op.rng      #} p (fromOperationType $ sRNG       v)
		{#set session_op.keylen   #} p keyLen
		{#set session_op.key      #} p keyPtr
		{#set session_op.mackeylen#} p mackeyLen
		{#set session_op.mackey   #} p mackeyPtr
		{#set session_op.ses      #} p (fromIntegral      $ sSes       v)

instance Storable Operation where
	sizeOf    _ = {#sizeof  crypt_op#}
	alignment _ = {#alignof crypt_op#}
	peek p = do
		vSes   <- {#get crypt_op.ses  #} p
		vOp    <- {#get crypt_op.op   #} p
		vFlags <- {#get crypt_op.flags#} p
		vLen   <- {#get crypt_op.len  #} p
		vSrc   <- {#get crypt_op.src  #} p
		vDst   <- {#get crypt_op.dst  #} p
		vMac   <- {#get crypt_op.mac  #} p
		vIV    <- {#get crypt_op.iv   #} p
		return Operation
			{ oSes   =          fromIntegral vSes
			, oOp    = toEnum $ fromIntegral vOp
			, oFlags =          fromIntegral vFlags
			, oLen   =          fromIntegral vLen
			, oSrc   =          castPtr      vSrc
			, oDst   =          castPtr      vDst
			, oMac   =          castPtr      vMac
			, oIV    =          castPtr      vIV
			}
	poke p v = do
		{#set crypt_op.ses  #} p (fromIntegral            $ oSes   v)
		{#set crypt_op.op   #} p (fromIntegral . fromEnum $ oOp    v)
		{#set crypt_op.flags#} p (fromIntegral            $ oFlags v)
		{#set crypt_op.len  #} p (fromIntegral            $ oLen   v)
		{#set crypt_op.src  #} p (castPtr                 $ oSrc   v)
		{#set crypt_op.dst  #} p (castPtr                 $ oDst   v)
		{#set crypt_op.mac  #} p (castPtr                 $ oMac   v)
		{#set crypt_op.iv   #} p (castPtr                 $ oIV    v)

instance Default OpenFileFlags where def = defaultFileFlags

data StartSession = StartSession
data Crypt        = Crypt
data EndSession   = EndSession
instance IOControl StartSession Session   where ioctlReq _ = fromIntegral . fromEnum $ CtlStartSession
instance IOControl Crypt        Operation where ioctlReq _ = fromIntegral . fromEnum $ CtlCrypt
instance IOControl EndSession   Word32    where ioctlReq _ = fromIntegral . fromEnum $ CtlEndSession

openCryptodev :: MonadIO m => Computation m Fd
openCryptodev = do
	fd <- reifyIOException "Could not open" (openFd "/dev/crypto" ReadWrite def def)
	liftIO $ addFinalizer fd (closeFd fd)
	return fd

startSession :: MonadIO m => Fd -> Session -> Computation m Word32
startSession cryptofd session
	= reifyIOException "Could not start cryptodev session;"
	$ sSes <$> ioctl cryptofd StartSession session

endSession :: MonadIO m => Fd -> Word32 -> Computation m ()
endSession cryptofd session
	= reifyIOException "Failed to end cryptodev session;"
	$ ioctl_ cryptofd EndSession session

operation :: MonadIO m => Fd -> Operation -> Computation m ()
operation cryptofd op
	= reifyIOException ("Operation " ++ show op ++ " failed;")
	$ ioctl_ cryptofd Crypt op

sessionOperation :: MonadIO m => Fd -> Session -> Operation -> Computation m ()
sessionOperation cryptofd session op = do
	sID    <- startSession cryptofd session
	crypt' <- delayFailure $ operation cryptofd op { oSes = sID }
	endSession cryptofd sID
	deliverFailure crypt'

ptrWords        :: ByteStringConversion (Computation IO) ByteString (Ptr Word8, Word32) r
hybridStringLen :: ByteStringConversion (Computation IO) ByteString (Ptr Word8, Int) r
mcuStringLen    :: ByteStringConversion IO (Maybe ByteString) CUStringLen r
ptrWords        = inComputation unsafeArbStringLen
hybridStringLen = inComputation unsafeArbStringLen
mcuStringLen    = useDefAsNothing cuStringLen

crypt cryptofd dir k t =
	allocaBytes lenK $ \out ->
	useAs ptrWords t $ \(ptrT, lenT) -> do
		sessionOperation cryptofd
			def { sCipher = Just CRYPTO_AES_ECB, sKey = Just k }
			def { oOp  = dir
				, oLen = lenT
				, oSrc = ptrT
				, oDst = out
				}
		pack hybridStringLen (out, lenK)
	where lenK = Data.ByteString.length k

aesImplementation = do
	cryptofd <- openCryptodev
	return Cipher
		{ encrypt = crypt cryptofd Encrypt
		, decrypt = crypt cryptofd Decrypt
		}

implementation = (unimplemented "kernel-crypto via cryptodev-linux") { aes = aesImplementation }

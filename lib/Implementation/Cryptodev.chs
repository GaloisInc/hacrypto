{-# LANGUAGE GeneralizedNewtypeDeriving, MultiParamTypeClasses #-}
module Implementation.Cryptodev (implementation) where

#include <crypto/cryptodev.h>
#include <asm-generic/ioctl.h>

import AlgorithmTypes
import Control.Monad
import Data.Bits
import Data.ByteString.Char8
import Data.Default
import Data.Functor
import Data.Word
import Foreign.C.Types
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import SuiteB
import System.Mem.Weak
import System.Posix.IO.ByteString
import System.Posix.IOCtl

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
instance Default Direction     where def = Encrypt
instance Default Flag          where def = 0
instance Default Session       where def = Session   def def def def def def
instance Default Operation     where def = Operation def def def def def def def def

toOperationType 0 = Nothing
toOperationType n = Just (toEnum (fromIntegral n))
fromOperationType Nothing  = 0
fromOperationType (Just o) = fromIntegral (fromEnum o)

-- for comparison, type CStringLen = (Ptr CChar, CInt)
type CUStringLen = (Ptr CUChar, CUInt)
useAsCUStringLen :: ByteString -> (CUStringLen -> IO a) -> IO a
useAsCUStringLen bs f = useAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr, fromIntegral len)

useMAsCUStringLen :: Maybe ByteString -> (CUStringLen -> IO a) -> IO a
useMAsCUStringLen Nothing   f = f (nullPtr, 0)
useMAsCUStringLen (Just bs) f = useAsCUStringLen bs f

packCUStringLen :: CUStringLen -> IO ByteString
packCUStringLen (ptr, len) = packCStringLen (castPtr ptr, fromIntegral len)

packMCUStringLen :: CUStringLen -> IO (Maybe ByteString)
packMCUStringLen (ptr, len)
	| ptr == nullPtr = return Nothing
	| otherwise      = Just <$> packCUStringLen (ptr, len)

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
		bsKey      <- packMCUStringLen (   vKey,    vKeylen)
		bsMacKey   <- packMCUStringLen (vMackey, vMackeylen)
		return Session
			{ sCipher    = toOperationType vCipher
			, sMac       = toOperationType vMac
			, sRNG       = toOperationType vRng
			, sKey       = bsKey
			, sMacKey    = bsMacKey
			, sSes       = fromIntegral vSes
			}
	poke p v = useMAsCUStringLen (sKey    v) $ \(   keyPtr,    keyLen) ->
	           useMAsCUStringLen (sMacKey v) $ \(mackeyPtr, mackeyLen) -> do
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

aesImplementation = do
	-- TODO: catch exceptions and put errno into the failing side of the return value
	cryptofd <- openFd (pack "/dev/crypto") ReadWrite def def
	addFinalizer cryptofd (closeFd cryptofd)
	return $ Right Cipher
		{ encrypt = \k t -> do
			sessionID <- sSes <$> ioctl cryptofd StartSession def
				{ sCipher = Just CRYPTO_AES_ECB
				, sKey    = Just k
				}
			let lenK = Data.ByteString.Char8.length k
			res <- allocaBytes lenK   $ \out ->
			       useAsCUStringLen t $ \(ptrT, lenT) -> do
			       	ioctl cryptofd Crypt def
			       		{ oSes = sessionID
			       		, oOp  = Encrypt
			       		, oLen = fromIntegral lenT
			       		, oSrc = castPtr      ptrT
			       		, oDst = out
			       		}
			       	packCStringLen (castPtr out, lenK)
			ioctl cryptofd EndSession sessionID
			return (Right res)
		, decrypt = \k t -> return (Left "not implemented yet")
		}

implementation = (unimplemented "kernel-crypto via cryptodev-linux") { aes = aesImplementation }

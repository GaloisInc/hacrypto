module Types
	( Value(..)
	, Equation(..)
	, Block(..)
	, Vectors(..)
	, Computation
	, ByteString
	, basicHex
	, basicDec
	, basicString
	) where

import Control.Monad
import Data.ByteString (ByteString, pack, unpack)
import Data.Char (digitToInt, isHexDigit, isSpace)
import Data.List
import Numeric
import Text.Regex.Applicative

data Value
	= Basic
		{ uninterpreted :: String
		, decimal       :: Maybe Integer
		, hexadecimal   :: Maybe ByteString
		}
	| Boolean Bool
	| SuccessReport
		{ success :: Bool
		, message :: String
		}
	| ErrorMessage String
	| Flag
	deriving (Eq, Ord, Read, Show)

basicHex    :: ByteString -> Value
basicDec    :: Integer    -> Value
basicString :: String     -> Value

basicHex    bs = Basic { uninterpreted = u, decimal = d, hexadecimal = h } where
	u = pprintHex bs
	d = parseDec u
	h = Just bs

basicDec    n  = Basic { uninterpreted = u, decimal = d, hexadecimal = h } where
	u = pprintDec n
	d = Just n
	h = parseHex u

basicString s  = Basic { uninterpreted = u, decimal = d, hexadecimal = h } where
	u = s
	d = parseDec u
	h = parseHex u

pprintDec :: Integer    -> String
pprintHex :: ByteString -> String
pprintDec = show
pprintHex = unpack >=> showByte where
	showByte n = [digits !! (n `rem` 16), digits !! (n `quot` 16)]
	(!!)   = genericIndex
	digits = "0123456789ABCDEF"

parseDec :: String -> Maybe Integer
parseHex :: String -> Maybe ByteString

parseDec s = case readDec s of
	(n, s):_ | all isSpace s -> Just n
	_ -> Nothing

parseHex s = pack <$> match pairs s where
	pairs    = many (liftA2 byte hexDigit hexDigit)
	byte a b = a*0x10 + b
	hexDigit = fromIntegral . digitToInt <$> psym isHexDigit

data Equation = Equation
	{ label :: String
	, value :: Value
	} deriving (Eq, Ord, Read, Show)

data Block = Block
	{ bracketed :: Bool
	, equations :: [Equation]
	} deriving (Eq, Ord, Read, Show)

data Vectors = Vectors
	{ header :: [String]
	, blocks :: [Block]
	} deriving (Eq, Ord, Read, Show)

type Computation m t = m (Either String t)

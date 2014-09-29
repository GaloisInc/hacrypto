module Types
	( Value(..)
	, Equation(..)
	, Block(..)
	, Vectors(..)
	, ByteString
	, basicHex
	, basicDec
	) where

import Data.ByteString (ByteString, pack)
import Data.Char (isSpace)

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

basicHex :: ByteString -> Value
basicDec :: Integer    -> Value

basicHex bs = Basic { uninterpreted = u, decimal = d, hexadecimal = h } where
	u = pprintHex bs
	d = case reads u of
	    	(n, s):_ | all isSpace s -> Just n
	    	_ -> Nothing
	h = Just bs

basicDec n = Basic { uninterpreted = u, decimal = d, hexadecimal = h } where
	u = show n
	d = Just n
	h = parseHex u

pprintHex :: ByteString -> String
parseHex  :: String -> Maybe ByteString
pprintHex _ = "" -- TODO
parseHex  _ = Just $ pack [] -- TODO

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

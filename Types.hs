module Types
	( Value(..)
	, Equation(..)
	, Block(..)
	, Vectors(..)
	, ByteString
	) where

import Data.ByteString (ByteString)

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

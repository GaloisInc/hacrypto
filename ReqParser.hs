{-# LANGUAGE FlexibleContexts, NoMonomorphismRestriction, Rank2Types #-}
module ReqParser
	( Value(..)
	, Equation(..)
	, Block(..)
	, Vectors(..)
	, parseVectors
	) where

import Data.ByteString (ByteString, pack)
import Data.Char
import Data.Default
import Data.Traversable
import Text.ParserCombinators.UU
import Text.ParserCombinators.UU.BasicInstances
import Text.ParserCombinators.UU.Utils hiding (pParens, pBrackets)

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

basicFromString :: String -> Value
basicFromString s = Basic s (execParserMaybe pIntegerRaw s) (execParserMaybe pHexRaw s) where
	pHexDigit      = digitToNum <$> pSatisfy isHexDigit (Insertion "hex digit" '0' 10)
	pHexRaw        = pack <$> many (createByte <$> pHexDigit <*> pHexDigit)
	createByte a b = a*0x10 + b
	digitToNum     = fromIntegral . digitToInt

execParserMaybe :: Parser a -> String -> Maybe a
execParserMaybe p s = guard (null errors) >> return v where
	(v, errors) = execParser p s

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

isLabel   c = isAlphaNum c || c `elem` "-_ "
isValue   c = isAlphaNum c || c `elem` "./"
isMessage c = c `notElem` "\r\n"

pManySepBy  p sep = pMany1SepBy p sep <|> pure []
pMany1SepBy p sep = (:) <$> p <*> many (sep *> p)
pLexeme     p     = p <* pSpace
pKeep       p     = (:[]) <$> p
pIgnore     p     =   []  <$  p
pLexSym           = pLexeme . pSym
pParens     p     = pLexSym '(' *> p <* pLexSym ')'
pBrackets   p     = pLexSym '[' *> p <* pLexSym ']'

pSpace      = pMunch (== ' ')
pRestOfLine = pMunch (`notElem` "\r\n") <* pEOL
pEOL        = pSym '\n' <|> (pSym '\r' *> pSym '\n')

pCommentNormal  = pLexSym '#' *> pRestOfLine
pCommentGarbage = pToken "NOTE: Salt lengths > SHA lengths is ONLY allowed for FIPS186-2 SigGenPSS testing for use with CMVP 1SUB, 2SUB and 4SUB report submissions."
pComment        = pKeep pCommentNormal <|> pKeep pCommentGarbage <|> pIgnore pEOL
pHeader         = concat <$> many pComment

pLabel = pList1 (pSatisfy isLabel (Insertion "equation label" 'X' 1000))
pParenthesizedMessage
	= pParens . pList1_ng . pSatisfy isMessage
	$ Insertion "parenthesized message contents" '-' 30

pErrorMessage = ErrorMessage <$> (pLexSym '?' *> pParenthesizedMessage)
pBoolean      =  (Boolean True  <$ pToken "True")
             <|> (Boolean False <$ pToken "False")
pSuccess =  SuccessReport . ('P' ==)
        <$> (pLexSym 'P' <|> pLexSym 'F')
        <*> pParenthesizedMessage
pValue =  pErrorMessage
      <|> pBoolean
     <<|> (basicFromString <$> pMunch isValue)
      <|> pSuccess

pEquationRaw    = Equation <$> pLexeme pLabel <* pLexSym '=' <*> pValue

pFlag           = flip Equation Flag <$> pMunch (`notElem` "=]")
pKeyPairGarbage = () <$ (pLexeme (pToken "mod") *> pLexSym '=')
pEquationParam  = opt pKeyPairGarbage () *> pEquationRaw
pParameters     = pBrackets (pManySepBy (pEquationParam <|> pFlag) (pLexSym ',')) <* pEOL

pFlagLine       = flip Equation Flag <$> pLabel
pEquationLine   = (pLexeme pEquationRaw <|> pFlagLine) <* pEOL

pBlock   =  (Block True . concat <$> pList1 pParameters  )
        <|> (Block False         <$> pList1 pEquationLine)
pBlocks  = concat <$> pMany1SepBy (pList1 pBlock) (pList1 pEOL)
pVectors = Vectors <$> pHeader <*> (pBlocks <* many pEOL <|> pure [])

parseVectors = execParser pVectors

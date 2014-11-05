{-# LANGUAGE FlexibleContexts, NoMonomorphismRestriction, Rank2Types #-}
module Parser (module Types, parseVectors) where

import Data.Char
import Data.Maybe
import Text.ParserCombinators.UU
import Text.ParserCombinators.UU.BasicInstances
import Text.ParserCombinators.UU.Utils hiding (pParens, pBrackets)
import Types

-- utilities {{{
execParserMaybe :: Parser a -> String -> Maybe a
execParserMaybe p s = guard (null errors) >> return v where
	(v, errors) = execParser p s

coalesceEqualBy :: (a -> a -> Bool) -> [a] -> Maybe a
coalesceEqualBy eq (x:xs) | all (eq x) xs = Just x
coalesceEqualBy _ _ = Nothing

coalesceEqual   :: Eq a =>             [a] -> Maybe a
coalesceEqualOn :: Eq b => (a -> b) -> [a] -> Maybe a
coalesceEqual     = coalesceEqualBy (==)
coalesceEqualOn f = coalesceEqualBy (\x -> (f x ==) . f)

eqAnnotations :: Eq a => [Annotated v a] -> Maybe (Annotated [v] a)
eqAnnotations vs = Annotated (annotated <$> vs) . annotation <$> coalesceEqualOn annotation vs
-- }}}

data Annotated v a = Annotated
	{ annotated  :: v
	, annotation :: a
	} deriving (Eq, Ord, Read, Show)

isLabel   c = isAlphaNum c || c `elem` "-_"
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

pLabelWord = pList1 (pSatisfy isLabel (Insertion "equation label" 'X' 1000))
pLabel = unwords <$> pMany1SepBy pLabelWord (pSym ' ')
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
     <<|> (basicString <$> pMunch isValue)
      <|> pSuccess

pEquationRaw   = (\label ws _eq ws' value -> Annotated (Equation label value) (Just (ws, ws')))
              <$> pLabel
              <*> pSpace
              <*> pSym '='
              <*> pSpace
              <*> pValue

annotatedFlag   = flip Annotated Nothing . flip Equation Flag

pFlag           = annotatedFlag <$> pMunch (`notElem` "=]")
pKeyPairGarbage = ModEq <$ (pLexeme (pToken "mod") *> pLexSym '=')
pEquationParam  = (,) <$> opt pKeyPairGarbage Brackets <*> pEquationRaw
pParameters     = pBrackets (pManySepBy (pEquationParam <|> ((,) Brackets <$> pFlag)) (pLexSym ',')) <* pEOL

pFlagLine       = annotatedFlag <$> pLabel
pEquationLine   = (pLexeme pEquationRaw <|> pFlagLine) <* pEOL

-- when there's just one line of parameters, use whatever kind it claims to be;
-- otherwise there isn't really a good way to combine different kinds of
-- parameters, so just say it's Multiline
identifyParameters lines = (kind, lines >>= map snd) where
	kind = case lines of
		[(k, _):_] -> k
		_          -> Multiline

coalesceWhitespaces spaces = case coalesceEqual (catMaybes spaces) of
	Just ("", "") -> Compact
	_ -> Spread

pBlock  =  mangle
       <$> (  (identifyParameters <$> pList1 pParameters  )
          <|> ((,) None           <$> pList1 pEquationLine)
           )
	where
	mangle (b, eqs) = Block b
		(coalesceWhitespaces (annotation <$> eqs))
		(annotated <$> eqs)
		0

onLast f [x] = [f x]
onLast f (x:xs) = x:onLast f xs
onLast f [] = []

pBlocks  = concat <$> many ((\bs eols -> onLast (\b -> b { padding = length eols }) bs) <$> pList1 pBlock <*> many pEOL)
pVectors = Vectors <$> pHeader <*> (pBlocks <|> pure [])

parseVectors = execParser pVectors

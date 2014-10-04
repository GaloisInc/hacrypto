{-# LANGUAGE NoMonomorphismRestriction #-}
module Test.AES (test) where

import Computation
import Control.Monad.Reader
import Data.Default
import Data.Foldable
import SuiteB
import Transducer

anyVal = asum [m <$ string (show m) | m <- [minBound..maxBound]]
mode = do3
	(many anySym)
	(header (string "AESVS " *> many anySym *> string " test data for " *> anyVal))
	(many anySym)
	(\_ mode _ -> do
		suite  <- ask
		cipher <- liftIO $ cipherAlg suite AES mode
		return (cipher, usesIV mode)
	)

chunk usesIV directionName inputName outputName crypt = do2
	(parameters $ flag directionName)
	(many . tests $ do4
		(int "COUNT")
		(hex "KEY")
		(if usesIV then hex "IV" else pure def)
		(hex inputName)
		(\_ key iv bytes -> emitHex outputName (liftComputation $ crypt key iv bytes))
	)
	(\_ _ -> return ())

chunks (cipher, usesIV)
	= many (chunk usesIV "ENCRYPT" "PLAINTEXT"  "CIPHERTEXT" (encrypt_ cipher) <|>
	        chunk usesIV "DECRYPT" "CIPHERTEXT" "PLAINTEXT"  (decrypt_ cipher))

test = vectors mode chunks

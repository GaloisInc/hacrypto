{-# LANGUAGE NoMonomorphismRestriction #-}
-- | An internal module. API subject to intense fluctuation. Use at your own
-- risk.
module Test.Util
	( module SuiteB
	, module Test.Util
	, module Transducer
	) where

import Control.Monad.Reader
import Data.Default
import SuiteB
import Transducer

modeHeader alg modeLine = do3
	(many anySym)
	(header modeLine)
	(many anySym)
	(\_ mode _ -> do
		suite  <- ask
		cipher <- lift . lift $ cipherAlg suite alg mode
		return (cipher, usesIV mode)
	)

chunk usesIV directionName keyName inputName outputName crypt = do2
	(parameters $ flag directionName)
	(many . tests $ do4
		(int "COUNT")
		(hex keyName)
		(if usesIV then hex "IV" else pure def)
		(hex inputName)
		(\_ key iv bytes -> emitHex outputName (lift . lift $ crypt key iv bytes))
	)
	(\_ _ -> return ())

chunks key (cipher, usesIV)
	= many (chunk usesIV "ENCRYPT" key "PLAINTEXT"  "CIPHERTEXT" (encrypt_ cipher) <|>
	        chunk usesIV "DECRYPT" key "CIPHERTEXT" "PLAINTEXT"  (decrypt_ cipher))

standardTest alg modeLine key = vectors (modeHeader alg modeLine) (chunks key)

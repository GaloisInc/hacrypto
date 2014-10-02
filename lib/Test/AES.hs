{-# LANGUAGE NoMonomorphismRestriction #-}
module Test.AES (test) where

import AlgorithmTypes
import Transducer

chunk directionName inputName outputName directionFunction = do2
	(parameters $ flag directionName)
	(many . tests $ do3
		(int "COUNT")
		(hex "KEY")
		(hex inputName)
		(\_ key bytes -> emitHex outputName (directionFunction key bytes))
	)
	(\_ _ -> return ())

chunks = many (chunk "ENCRYPT" "PLAINTEXT"  "CIPHERTEXT" callEncrypt <|>
               chunk "DECRYPT" "CIPHERTEXT" "PLAINTEXT"  callDecrypt)

test = anyHeader chunks

{-# LANGUAGE NoMonomorphismRestriction #-}
module Test.AES (aes) where

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

aesBlocks = many (chunk "ENCRYPT" "PLAINTEXT"  "CIPHERTEXT" encrypt <|>
                  chunk "DECRYPT" "CIPHERTEXT" "PLAINTEXT"  decrypt)

aes = anyHeader aesBlocks

module AES where

import Data.ByteString (pack)
import Transducer

-- TODO: probably need to return an Either String ByteString or something so we
-- can report errors
zero = pack []
encrypt k t = putStr "Encrypting " >> print (k, t) >> return zero
decrypt k t = putStr "Decrypting " >> print (k, t) >> return zero

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

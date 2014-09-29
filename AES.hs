module AES (aes) where

import Transducer

encrypt k t = putStr "Encrypting " >> print (k, t) >> return (Left "AES encryption not supported")
decrypt k t = putStr "Decrypting " >> print (k, t) >> return (Left "AES decryption not supported")

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

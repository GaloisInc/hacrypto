module Implementation.Debug (implementation) where

import Computation
import SuiteB

libraryName = "debug mode"
putStrs = liftIO . putStrLn . unwords
implementation = SuiteB
	{ cipherAlg = \alg mode -> return $ cipher
		(\k iv t -> report "Encrypting" k iv t mode >> unimplemented_ libraryName alg mode)
		(\k iv t -> report "Decrypting" k iv t mode >> unimplemented_ libraryName alg mode)
	,   hashAlg = \alg -> return Hash
		{ update   = \t -> putStrs ["Updating", show t] >> unimplemented_ libraryName alg
		, finalize =       putStrs ["Finalizing"]       >> unimplemented_ libraryName alg
		, hash     = \t -> putStrs ["Hashing" , show t] >> unimplemented_ libraryName alg
		}
	}
	where report s k iv t mode = putStrs [s, show (k, t), "with IV", if usesIV mode then show iv else "(none)"]

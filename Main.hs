import Control.Applicative
import Control.Monad
import Implementation.Debug
import Parser
import PPrint
import SuiteB
import System.Environment
import System.Exit
import System.IO
import Test.AES
import Transducer

main = getArgs >>= mapM_ checkFile
checkFile f = do
	(v, es) <- parseVectors <$> readFile f
	case es of
		[]  -> do
			-- TODO: write a real test runner that actually does error-checking
			-- and stuff, instead of this incomplete pattern match
			Right impl <- aes implementation
			v_ <- runTransformer test impl v
			case v_ of
				Just v' -> writeFile (f ++ ".out") (pprint v')
				Nothing -> hPutStrLn stderr f >> hPutStrLn stderr "\tRequest file didn't match AES specs"
		e:_ -> hPutStrLn stderr f >> hPrint stderr e

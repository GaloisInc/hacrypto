import Control.Applicative
import Control.Monad
import Implementation.Cryptodev
import Parser
import PPrint
import SuiteB
import System.Environment
import System.Exit
import System.IO
import Test.AES
import Transducer
import Types

main = getArgs >>= mapM_ checkFile
-- TODO: checkFile is getting awfully deeply nested; use Computation instead
checkFile f = do
	(v, es) <- parseVectors <$> readFile f
	case es of
		e:_ -> hPutStrLn stderr f >> hPrint stderr e
		[]  -> do
			impl_ <- runExceptT $ aes implementation
			case impl_ of
				Left  error -> hPutStrLn stderr error
				Right impl  -> do
					v_ <- runTransformer test impl v
					case v_ of
						Just v' -> writeFile (f ++ ".out") (pprint v')
						Nothing -> hPutStrLn stderr f >> hPutStrLn stderr "\tRequest file didn't match AES specs"

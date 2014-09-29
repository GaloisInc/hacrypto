import AES
import Control.Applicative
import Control.Monad
import Control.Monad.Trans.Maybe
import Parser
import PPrint
import System.Environment
import System.Exit
import System.IO

main = getArgs >>= mapM_ checkFile
checkFile f = do
	(v, es) <- parseVectors <$> readFile f
	case es of
		[]  -> do
			v_ <- runMaybeT $ aes v
			case v_ of
				Just v' -> writeFile (f ++ ".out") (pprint v')
				Nothing -> hPutStrLn stderr "Request file didn't match AES specs"
		e:_ -> hPutStrLn stderr f >> hPrint stderr e

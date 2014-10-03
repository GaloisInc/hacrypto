import Computation
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

main = getArgs >>= mapM_ (runAndReport . checkFile)
runAndReport = runComputation >=> either (hPutStrLn stderr) (\_ -> return ())
checkFile f = do
	(v, es) <- liftIO $ parseVectors <$> readFile f
	when (not $ null es) (throwError $ f ++ "\n" ++ show (head es))
	impl    <- aes implementation
	v'      <- runTransformer test impl v
	       <?> f ++ "\n\tRequest file didn't match AES specs"
	reifyIOException "Couldn't write" (writeFile (f ++ ".out") (pprint v'))

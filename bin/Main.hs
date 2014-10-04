import Computation
import Control.Applicative
import Control.Monad
import Data.Char
import Implementation.Cryptodev
import Parser
import PPrint
import SuiteB
import System.Environment
import System.Exit
import System.IO
import Test.AES
import Transducer

main = getArgs >>= mapM_ (runAndReport . processFile)
runAndReport = runComputation >=> either (hPutStrLn stderr) (\_ -> return ())

readFile'  =  reifyIOException "Couldn't open"    .  readFile
writeFile' = (reifyIOException "Couldn't open" .) . writeFile

parseVectors' f s = case parseVectors s of
	(v, [])  -> return v
	(_, e:_) -> throwError $ f ++ "\n" ++ show e

processFile :: FilePath -> Computation IO ()
processFile f = do
	s  <- readFile' f
	v  <- parseVectors' f s
	v' <- runTransformer test implementation v
	writeFile' (f ++ ".out") (pprint v')

-- TODO: move this closer and closer to closeEnough = (==)
closeEnough a b = filter (not . isSpace) a == filter (not . isSpace) b

checkRoundtrip :: FilePath -> Computation IO ()
checkRoundtrip f = do
	s  <- readFile' f
	s' <- pprint <$> parseVectors' f s
	unless (closeEnough s s') $ do
		writeFile' "out" s'
		throwError $ f ++ "\n\tdoesn't roundtrip; output written to out"

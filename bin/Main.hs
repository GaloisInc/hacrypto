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

main = getArgs >>= mapM_ (runAndReport . checkRoundtrip)
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

normalizeNewlines ('\r':'\n':rest) = '\n':normalizeNewlines rest
normalizeNewlines (c:rest) = c:normalizeNewlines rest
normalizeNewlines [] = []

normalizeRepeats (x:y:rest) | isSpace x && isSpace y && x == y = normalizeRepeats (y:rest)
normalizeRepeats (c:rest) = c:normalizeRepeats rest
normalizeRepeats [] = []

normalizeEndlineSpace (' ':xs) = case span (==' ') xs of
	(ws, '\n':rest) -> '\n':normalizeEndlineSpace rest
	(ws, rest) -> " " ++ ws ++ normalizeEndlineSpace rest
normalizeEndlineSpace (x:xs) = x : normalizeEndlineSpace xs
normalizeEndlineSpace [] = []

-- TODO: move this closer and closer to id
normalize = normalizeEndlineSpace . normalizeNewlines
closeEnough a b = normalize a == normalize b

checkRoundtrip :: FilePath -> Computation IO ()
checkRoundtrip f = do
	s  <- readFile' f
	s' <- pprint <$> parseVectors' f s
	unless (closeEnough s s') $ do
		writeFile' "out" s'
		throwError $ f ++ "\n\tdoesn't roundtrip; output written to out"

checkParse :: FilePath -> Computation IO ()
checkParse f = readFile' f >>= parseVectors' f >> return ()

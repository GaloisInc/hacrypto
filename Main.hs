import Control.Applicative
import Control.Monad
import ReqParser
import System.Environment
import System.Exit

main = getArgs >>= mapM_ checkFile
checkFile f = do
	(v, es) <- parseVectors <$> readFile f
	unless (null es) (putStrLn f >> print (head es))

import Data.ByteString (ByteString)
import Control.Monad (replicateM)
import Data.List (unfoldr)

-- From the 'entropy' package - for non-determinstic random bits.
-- These values come from
--    - RDRAND (when on an x86-64 system with said instruction and using new enough compilers)
--    - /dev/urandom (when on a nix system)
--    - Windows crypt-api (obvious)
import System.Entropy

-- From the DRBG package
-- The CtrDRBG will use NIST SP800-90 + AES-CTR + a seed you provide to
-- produce cryptographically strong random values.
import Crypto.Random.DRBG

-- To throw exceptions instead of get 'Either' results.
import Crypto.Classes.Exceptions as X

-- Obtain N blocks of 1MB random values based on the given seed
-- (Seed must be 32 bytes or larger)
pseudoRandom :: ByteString -> Int -> [ByteString]
pseudoRandom seed n =
     let g = X.newGen seed :: CtrDRBG
     in unfoldr (\(gen,cnt) -> if cnt == 0
                                  then Nothing
                                  else let (rand,newGen) = X.genBytes (2^20) gen
                                       in Just (rand, (newGen,cnt-1)))
                (g,n)

realRandom :: Int -> IO [ByteString]
realRandom n = replicateM n (getEntropy (2^20))

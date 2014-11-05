{-# LANGUAGE NoMonomorphismRestriction #-}
module Test.TDES (test) where

import Test.Util

test = standardTest TDES modeLine "KEYs"
modeLine = many anySym *> anyVal

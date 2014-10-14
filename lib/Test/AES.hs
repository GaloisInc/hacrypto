{-# LANGUAGE NoMonomorphismRestriction #-}
module Test.AES (test) where

import Test.Util

test = standardTest AES modeLine "KEY"
modeLine = string "AESVS " *> many anySym *> string " test data for " *> anyVal

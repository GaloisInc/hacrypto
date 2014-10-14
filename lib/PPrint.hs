module PPrint (module Types, PPrint(..)) where

import Data.List
import Types

class PPrint a where pprint :: a -> String

instance PPrint Value where
	pprint Basic { uninterpreted = s } = s
	pprint (Boolean b) = show b
	pprint SuccessReport { success = b, message = m } = concat
		[ if b then "P" else "F"
		, " (", m, ")"
		]
	pprint (ErrorMessage s) = "? (" ++ s ++ ")"
	pprint Flag = ""

-- TODO: do spaces really always occur? is it okay for them to always occur?
instance PPrint Equation where
	pprint Equation { label = s, value = v } = concat
		[ s
		, if v == Flag then "" else " = "
		, pprint v
		]

instance PPrint Block where
	pprint Block { bracketing = b, equations = e } = connect b (map pprint e) where
		bracket s = "[" ++ s ++ "]"
		onHead f (x:xs) = f x:xs
		onHead f []     = []
		connect None      = unlines
		connect Brackets  = bracket . intercalate ","
		connect ModEq     = bracket . intercalate ", " . onHead ("mod = " ++)
		connect Multiline = unlines . map bracket

instance PPrint Vectors where
	pprint Vectors { headers = h, blocks = b }
		= intercalate "\n"
		$ unlines (map comment h)
		: map pprint b

comment s
	| s == unhashedComment = s
	| otherwise = "# " ++ s
	where
	unhashedComment = "NOTE: Salt lengths > SHA lengths is ONLY allowed for FIPS186-2 SigGenPSS testing for use with CMVP 1SUB, 2SUB and 4SUB report submissions."

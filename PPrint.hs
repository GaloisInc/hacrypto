module PPrint (module Types, PPrint(..)) where

import Data.List
import Types

class PPrint a where pprint :: a -> String

instance PPrint Value where
	pprint Basic { uninterpreted = s } = s
	pprint (Boolean b) = show b
	pprint SuccessReport { success = b, message = m } = concat
		[ if b then "P" else "F"
		, "(", m, ")"
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

-- TODO: this isn't right, since bracketed blocks can look like any of these:
-- 1. [k1 = v1]
--    [k2 = v2]
-- 2. [k1 = v1, k2 = v2]
-- 3. [mod = k1 = v1, k2 = v2]
-- ...but we only produce output of kind (1). The parser will have to store
-- this information and hide it from clients other than pprint somehow (or at
-- least make it easy for other clients to ignore the extra information).
instance PPrint Block where
	pprint Block { bracketed = b, equations = es } = unlines
		[ concat
			[ ['[' | b]
			, pprint e
			, [']' | b]
			]
		| e <- es
		]

-- TODO: also not quite right, because of the ridiculous special-case we have
-- for the salt lengths comment, sigh (search for "Salt lengths" in the parser
-- code)
instance PPrint Vectors where
	pprint Vectors { header = h, blocks = b }
		= intercalate "\n"
		$ unlines (map ("# "++) h)
		: map pprint b

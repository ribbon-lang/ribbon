module Language.Ribbon.Syntax.Binding where

import Text.Pretty

import Language.Ribbon.Syntax.Category
import Language.Ribbon.Syntax.Fixity
import Language.Ribbon.Syntax.Precedence




-- | Binds an overloaded name to a value, either a @Ref@ or a @Path@,
--   depending on compilation phase. The @Fixity@ and @Precedence@ of
--   this usage of the overload are stored here as well
data Binding e
    = Binding
    { fixity :: !ExactFixity
    , precedence :: !Precedence
    , elem :: !e
    }
    deriving Show

instance CatOverloaded e => CatOverloaded (Binding e) where
    overloadCategory = overloadCategory . (.elem)

instance FixOverloaded (Binding e) where
    overloadFixity = exactFixityToOverload . (.fixity)

instance CatOverloaded e => Eq (Binding e) where
    a == b = compare a b == EQ

instance CatOverloaded e => Ord (Binding e) where
    compare a b
         = compare (overloadCategory a) (overloadCategory b)
        <> compare (overloadFixity a) (overloadFixity b)

instance Pretty e => Pretty (Binding e) where
    pPrintPrec lvl _ (Binding f p i) =
        hang (pPrintPrec lvl 0 f <+> pPrintPrec lvl 0 p <+> "::") do
            pPrintPrec lvl 0 i
module Language.Ribbon.Syntax.Path where

import Data.Foldable qualified as Fold

import Data.Sequence (Seq)
import Data.Sequence qualified as Seq

import Data.Tag
import Data.Attr

import Text.Pretty

import Language.Ribbon.Syntax.Fixity
import Language.Ribbon.Syntax.Category




-- | A definition name, without qualification.
--   Either a symbol or an identifier; never a reserved character sequence
newtype Name
    = Name
    { value :: String }
    deriving (Eq, Ord, Show)

instance Pretty Name where
    pPrint (Name n) = text n



-- | A path to a definition, with a base to start resolving from,
--   and specifiers on names
data Path
    = Path
    { base :: !(ATag PathBase)
    , components :: !(Seq (ATag PathComponent))
    }
    deriving (Eq, Ord, Show)

instance Pretty Path where
    pPrintPrec lvl _ p@(Path b cs) =
        let csd = hcat $ punctuate "/" (pPrintPrec lvl 0 <$> Fold.toList cs)
        in if pathRequiresSlash p
            then pPrintPrec lvl 0 b <> "/" <> csd
            else pPrintPrec lvl 0 b <> csd

pathRequiresSlash :: Path -> Bool
pathRequiresSlash lp
        = not (Seq.null lp.components)
    || pathBaseRequiresSlash lp.base.value

instance CatOverloaded Path where
    overloadCategory (Path _ (_ Seq.:|> c)) = overloadCategory c.value
    overloadCategory _ = ONamespace

instance FixOverloaded Path where
    overloadFixity (Path _ (_ Seq.:|> c)) = overloadFixity c.value
    overloadFixity _ = OAtomPrefix


-- | The base component of a @Path@,
--   specifying where to begin looking up components
data PathBase
    -- | Start at the root of the active module
    = PbRoot
    -- | Start in the current namespace
    | PbThis
    -- | Start in a given module
    | PbModule !Name
    -- | Start in a given file
    | PbFile !FilePath
    -- | Start in a given number of levels above the current namespace
    | PbUp !Int
    deriving (Eq, Ord, Show)

instance Pretty PathBase where
    pPrint = \case
        PbRoot -> "/"
        PbThis -> "./"
        PbModule n -> "module" <+> pPrint n
        PbFile f -> "file" <+> shown f
        PbUp i -> text (concat $ replicate i "../")

pathBaseRequiresSlash :: PathBase -> Bool
pathBaseRequiresSlash = \case
    PbModule _ -> True
    PbFile _ -> True
    _ -> False

-- | A component of a @Path@, specifying a name to look up, with a specifier
data PathComponent
    -- | Specifies a non-namespace definition that may have
    --   a specific fixity and/or a category
    = PcItem !OverloadFixity !OverloadCategory !Name
    deriving (Eq, Ord, Show)

instance Pretty PathComponent where
    pPrint = \case
        PcItem f k n -> pPrint f <+> pPrint k <+> pPrint n

instance CatOverloaded PathComponent where
    overloadCategory (PcItem _ k _) = k

instance FixOverloaded PathComponent where
    overloadFixity (PcItem f _ _) = f
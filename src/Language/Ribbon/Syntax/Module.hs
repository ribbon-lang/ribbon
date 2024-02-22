module Language.Ribbon.Syntax.Module where

import Data.Sequence (Seq)
import Data.Map.Strict (Map)

import Data.Attr

import Language.Ribbon.Lexical

import Language.Ribbon.Syntax.Ref
import Language.Ribbon.Syntax.Group
import Language.Ribbon.Syntax.Path
import Language.Ribbon.Syntax.Data
import Language.Ribbon.Syntax.Scheme
import Language.Ribbon.Syntax.Type
import Language.Ribbon.Syntax.Value



-- | An analysis context component, storing completed module's information.
--   Provides a lookup table from @(name string, version)@ pairs,
--   to their respective references
data ModuleContext
    = ModuleContext
    { modules :: !(RefMap FinalModule)
    , moduleLookup :: !(Map (String, Version) Ref)
    }

-- | A module that has been fully parsed
type FinalModule
    = Module
        Type
        Value
        ResolvedBlobs

-- | A module that has been partially parsed, and is awaiting name resolution
type ProtoModule
    = Module
        (Seq [ATag Token])
        (Seq [ATag Token])
        UnresolvedImports


-- | Parametric type storing all the elements of a module,
--   with their form depending on compilation phase.
--   A given @Ref@ may be bound to multiple rows of the module,
--   for example a value definition may have an entry in
--   @values@, @quantifiers@, @qualifiers@, and @types@.
--   Types with bodies are stored as @groups@, @quantifiers@, and @qualifiers@
--   The root namespace is always stored in @Ref Namespace modId 0@
data Module t v i
    = Module
    { groups      :: !(RefMap (Def Group))
    , imports     :: !(RefMap (Def i))
    , quantifiers :: !(RefMap (Def Quantifier))
    , qualifiers  :: !(RefMap (Def (Qualifier t)))
    , fields      :: !(RefMap (Def (FieldType t)))
    , types       :: !(RefMap (Def t))
    , values      :: !(RefMap (Def v))

    , files :: !(Map FilePath Ref)
    , dependencies :: !(Map Name Ref)
    }
%
% (c) The University of Glasgow 2006
% (c) The GRASP/AQUA Project, Glasgow University, 1992-1998
%
\section[TcType]{Types used in the typechecker}

This module provides the Type interface for front-end parts of the 
compiler.  These parts 

	* treat "source types" as opaque: 
		newtypes, and predicates are meaningful. 
	* look through usage types

The "tc" prefix is for "TypeChecker", because the type checker
is the principal client.

\begin{code}
module TcType (
  --------------------------------
  -- Types 
  TcType, TcSigmaType, TcRhoType, TcTauType, TcPredType, TcThetaType, 
  TcTyVar, TcTyVarSet, TcKind, TcCoVar,

  --------------------------------
  -- MetaDetails
  UserTypeCtxt(..), pprUserTypeCtxt,
  TcTyVarDetails(..), pprTcTyVarDetails,
  MetaDetails(Flexi, Indirect), MetaInfo(..), 
  SkolemInfo(..), pprSkolTvBinding, pprSkolInfo,
  isImmutableTyVar, isSkolemTyVar, isMetaTyVar,  isMetaTyVarTy,
  isSigTyVar, isOverlappableTyVar,  isTyConableTyVar,
  metaTvRef, 
  isFlexi, isIndirect, isUnkSkol, isRuntimeUnkSkol,

  --------------------------------
  -- Builders
  mkPhiTy, mkSigmaTy, 

  --------------------------------
  -- Splitters  
  -- These are important because they do not look through newtypes
  tcView,
  tcSplitForAllTys, tcSplitPhiTy, tcSplitPredFunTy_maybe,
  tcSplitFunTy_maybe, tcSplitFunTys, tcFunArgTy, tcFunResultTy, tcSplitFunTysN,
  tcSplitTyConApp, tcSplitTyConApp_maybe, tcTyConAppTyCon, tcTyConAppArgs,
  tcSplitAppTy_maybe, tcSplitAppTy, tcSplitAppTys, repSplitAppTy_maybe,
  tcInstHeadTyNotSynonym, tcInstHeadTyAppAllTyVars,
  tcGetTyVar_maybe, tcGetTyVar,
  tcSplitSigmaTy, tcDeepSplitSigmaTy_maybe, 

  ---------------------------------
  -- Predicates. 
  -- Again, newtypes are opaque
  tcEqType, tcEqTypes, tcEqPred, tcCmpType, tcCmpTypes, tcCmpPred, tcEqTypeX,
  eqKind, 
  isSigmaTy, isOverloadedTy, isRigidTy, 
  isDoubleTy, isFloatTy, isIntTy, isWordTy, isStringTy,
  isIntegerTy, isBoolTy, isUnitTy, isCharTy,
  isTauTy, isTauTyCon, tcIsTyVarTy, tcIsForAllTy, 
  isSynFamilyTyConApp,

  ---------------------------------
  -- Misc type manipulators
  deNoteType,
  tyClsNamesOfType, tyClsNamesOfDFunHead, 
  getDFunTyKey,

  ---------------------------------
  -- Predicate types  
  getClassPredTys_maybe, getClassPredTys, 
  isClassPred, isTyVarClassPred, isEqPred, 
  mkClassPred, mkIPPred, tcSplitPredTy_maybe, 
  mkDictTy, evVarPred,
  isPredTy, isDictTy, isDictLikeTy,
  tcSplitDFunTy, tcSplitDFunHead, predTyUnique, 
  isIPPred, 
  isRefineableTy, isRefineablePred,

  -- * Tidying type related things up for printing
  tidyType,      tidyTypes,
  tidyOpenType,  tidyOpenTypes,
  tidyTyVarBndr, tidyFreeTyVars,
  tidyOpenTyVar, tidyOpenTyVars,
  tidyTopType,   tidyPred,
  tidyKind, tidySkolemTyVar,

  ---------------------------------
  -- Foreign import and export
  isFFIArgumentTy,     -- :: DynFlags -> Safety -> Type -> Bool
  isFFIImportResultTy, -- :: DynFlags -> Type -> Bool
  isFFIExportResultTy, -- :: Type -> Bool
  isFFIExternalTy,     -- :: Type -> Bool
  isFFIDynArgumentTy,  -- :: Type -> Bool
  isFFIDynResultTy,    -- :: Type -> Bool
  isFFIPrimArgumentTy, -- :: DynFlags -> Type -> Bool
  isFFIPrimResultTy,   -- :: DynFlags -> Type -> Bool
  isFFILabelTy,        -- :: Type -> Bool
  isFFIDotnetTy,       -- :: DynFlags -> Type -> Bool
  isFFIDotnetObjTy,    -- :: Type -> Bool
  isFFITy,	       -- :: Type -> Bool
  isFunPtrTy,          -- :: Type -> Bool
  tcSplitIOType_maybe, -- :: Type -> Maybe Type  

  --------------------------------
  -- Rexported from Coercion
  typeKind,

  --------------------------------
  -- Rexported from Type
  Kind, 	-- Stuff to do with kinds is insensitive to pre/post Tc
  unliftedTypeKind, liftedTypeKind, argTypeKind,
  openTypeKind, mkArrowKind, mkArrowKinds, 
  isLiftedTypeKind, isUnliftedTypeKind, isSubOpenTypeKind, 
  isSubArgTypeKind, isSubKind, splitKindFunTys, defaultKind,
  kindVarRef, mkKindVar,  

  Type, PredType(..), ThetaType, 
  mkForAllTy, mkForAllTys, 
  mkFunTy, mkFunTys, zipFunTys, 
  mkTyConApp, mkAppTy, mkAppTys, applyTy, applyTys,
  mkTyVarTy, mkTyVarTys, mkTyConTy, mkPredTy, mkPredTys, 

  -- Type substitutions
  TvSubst(..), 	-- Representation visible to a few friends
  TvSubstEnv, emptyTvSubst, substEqSpec,
  mkOpenTvSubst, zipOpenTvSubst, zipTopTvSubst, 
  mkTopTvSubst, notElemTvSubst, unionTvSubst,
  getTvSubstEnv, setTvSubstEnv, getTvInScope, extendTvInScope, lookupTyVar,
  extendTvSubst, extendTvSubstList, isInScope, mkTvSubst, zipTyEnv,
  substTy, substTys, substTyWith, substTheta, substTyVar, substTyVars, substTyVarBndr,

  isUnLiftedType,	-- Source types are always lifted
  isUnboxedTupleType,	-- Ditto
  isPrimitiveType, 

  tyVarsOfType, tyVarsOfTypes, tyVarsOfPred, tyVarsOfTheta,
  tcTyVarsOfType, tcTyVarsOfTypes, tcTyVarsOfPred, exactTyVarsOfType,
  exactTyVarsOfTypes, 

  pprKind, pprParendKind,
  pprType, pprParendType, pprTypeApp, pprTyThingCategory,
  pprPred, pprTheta, pprThetaArrow, pprClassPred

  ) where

#include "HsVersions.h"

-- friends:
import TypeRep
import DataCon
import Class
import Var
import ForeignCall
import VarSet
import Type
import Coercion
import TyCon
import HsExpr( HsMatchContext )

-- others:
import DynFlags
import Name
import NameSet
import VarEnv
import PrelNames
import TysWiredIn
import BasicTypes
import Util
import Maybes
import ListSetOps
import Outputable
import FastString

import Data.List( mapAccumL )
import Data.IORef
\end{code}

%************************************************************************
%*									*
\subsection{Types}
%*									*
%************************************************************************

The type checker divides the generic Type world into the 
following more structured beasts:

sigma ::= forall tyvars. phi
	-- A sigma type is a qualified type
	--
	-- Note that even if 'tyvars' is empty, theta
	-- may not be: e.g.   (?x::Int) => Int

	-- Note that 'sigma' is in prenex form:
	-- all the foralls are at the front.
	-- A 'phi' type has no foralls to the right of
	-- an arrow

phi :: theta => rho

rho ::= sigma -> rho
     |  tau

-- A 'tau' type has no quantification anywhere
-- Note that the args of a type constructor must be taus
tau ::= tyvar
     |  tycon tau_1 .. tau_n
     |  tau_1 tau_2
     |  tau_1 -> tau_2

-- In all cases, a (saturated) type synonym application is legal,
-- provided it expands to the required form.

\begin{code}
type TcTyVar = TyVar  	-- Used only during type inference
type TcCoVar = CoVar  	-- Used only during type inference; mutable
type TcType = Type 	-- A TcType can have mutable type variables
	-- Invariant on ForAllTy in TcTypes:
	-- 	forall a. T
	-- a cannot occur inside a MutTyVar in T; that is,
	-- T is "flattened" before quantifying over a

-- These types do not have boxy type variables in them
type TcPredType     = PredType
type TcThetaType    = ThetaType
type TcSigmaType    = TcType
type TcRhoType      = TcType
type TcTauType      = TcType
type TcKind         = Kind
type TcTyVarSet     = TyVarSet
\end{code}


%************************************************************************
%*									*
\subsection{TyVarDetails}
%*									*
%************************************************************************

TyVarDetails gives extra info about type variables, used during type
checking.  It's attached to mutable type variables only.
It's knot-tied back to Var.lhs.  There is no reason in principle
why Var.lhs shouldn't actually have the definition, but it "belongs" here.


Note [Signature skolems]
~~~~~~~~~~~~~~~~~~~~~~~~
Consider this

  x :: [a]
  y :: b
  (x,y,z) = ([y,z], z, head x)

Here, x and y have type sigs, which go into the environment.  We used to
instantiate their types with skolem constants, and push those types into
the RHS, so we'd typecheck the RHS with type
	( [a*], b*, c )
where a*, b* are skolem constants, and c is an ordinary meta type varible.

The trouble is that the occurrences of z in the RHS force a* and b* to 
be the *same*, so we can't make them into skolem constants that don't unify
with each other.  Alas.

One solution would be insist that in the above defn the programmer uses
the same type variable in both type signatures.  But that takes explanation.

The alternative (currently implemented) is to have a special kind of skolem
constant, SigTv, which can unify with other SigTvs.  These are *not* treated
as righd for the purposes of GADTs.  And they are used *only* for pattern 
bindings and mutually recursive function bindings.  See the function
TcBinds.tcInstSig, and its use_skols parameter.


\begin{code}
-- A TyVarDetails is inside a TyVar
data TcTyVarDetails
  = SkolemTv SkolemInfo	  -- A skolem constant

  | FlatSkol TcType	  
           -- The "skolem" obtained by flattening during
    	   -- constraint simplification
    
           -- In comments we will use the notation alpha[flat = ty]
           -- to represent a flattening skolem variable alpha
           -- identified with type ty.
          
  | MetaTv MetaInfo (IORef MetaDetails)

data MetaDetails
  = Flexi  -- Flexi type variables unify to become Indirects  
  | Indirect TcType

data MetaInfo 
   = TauTv	   -- This MetaTv is an ordinary unification variable
     		   -- A TauTv is always filled in with a tau-type, which
		   -- never contains any ForAlls 

   | SigTv Name	   -- A variant of TauTv, except that it should not be
		   -- unified with a type, only with a type variable
		   -- SigTvs are only distinguished to improve error messages
		   --      see Note [Signature skolems]        
		   --      The MetaDetails, if filled in, will 
		   --      always be another SigTv or a SkolemTv
		   -- The Name is the name of the function from whose
		   -- type signature we got this skolem

   | TcsTv	   -- A MetaTv allocated by the constraint solver
     		   -- Its particular property is that it is always "touchable"
		   -- Nevertheless, the constraint solver has to try to guess
		   -- what type to instantiate it to

----------------------------------
-- SkolemInfo describes a site where 
--   a) type variables are skolemised
--   b) an implication constraint is generated
data SkolemInfo
  = SigSkol UserTypeCtxt	-- A skolem that is created by instantiating
				-- a programmer-supplied type signature
				-- Location of the binding site is on the TyVar

	-- The rest are for non-scoped skolems
  | ClsSkol Class	-- Bound at a class decl
  | InstSkol 		-- Bound at an instance decl
  | FamInstSkol 	-- Bound at a family instance decl
  | PatSkol 	        -- An existential type variable bound by a pattern for
      DataCon           -- a data constructor with an existential type.
      (HsMatchContext Name)	
	     --	e.g.   data T = forall a. Eq a => MkT a
	     --        f (MkT x) = ...
	     -- The pattern MkT x will allocate an existential type
	     -- variable for 'a'.  

  | ArrowSkol 	  	-- An arrow form (see TcArrows)

  | IPSkol [IPName Name]  -- Binding site of an implicit parameter

  | RuleSkol RuleName	-- The LHS of a RULE
  | GenSkol TcType	-- Bound when doing a subsumption check for ty

  | RuntimeUnkSkol      -- a type variable used to represent an unknown
                        -- runtime type (used in the GHCi debugger)

  | UnkSkol		-- Unhelpful info (until I improve it)

-------------------------------------
-- UserTypeCtxt describes the places where a 
-- programmer-written type signature can occur
-- Like SkolemInfo, no location info
data UserTypeCtxt 
  = FunSigCtxt Name	-- Function type signature
			-- Also used for types in SPECIALISE pragmas
  | ExprSigCtxt		-- Expression type signature
  | ConArgCtxt Name	-- Data constructor argument
  | TySynCtxt Name	-- RHS of a type synonym decl
  | GenPatCtxt		-- Pattern in generic decl
			-- 	f{| a+b |} (Inl x) = ...
  | LamPatSigCtxt		-- Type sig in lambda pattern
			-- 	f (x::t) = ...
  | BindPatSigCtxt	-- Type sig in pattern binding pattern
			--	(x::t, y) = e
  | ResSigCtxt		-- Result type sig
			-- 	f x :: t = ....
  | ForSigCtxt Name	-- Foreign inport or export signature
  | DefaultDeclCtxt	-- Types in a default declaration
  | SpecInstCtxt	-- SPECIALISE instance pragma
  | ThBrackCtxt		-- Template Haskell type brackets [t| ... |]

-- Notes re TySynCtxt
-- We allow type synonyms that aren't types; e.g.  type List = []
--
-- If the RHS mentions tyvars that aren't in scope, we'll 
-- quantify over them:
--	e.g. 	type T = a->a
-- will become	type T = forall a. a->a
--
-- With gla-exts that's right, but for H98 we should complain. 

---------------------------------
-- Kind variables:

mkKindName :: Unique -> Name
mkKindName unique = mkSystemName unique kind_var_occ

kindVarRef :: KindVar -> IORef MetaDetails
kindVarRef tc = 
  ASSERT ( isTcTyVar tc )
  case tcTyVarDetails tc of
    MetaTv TauTv ref -> ref
    _                -> pprPanic "kindVarRef" (ppr tc)

mkKindVar :: Unique -> IORef MetaDetails -> KindVar
mkKindVar u r 
  = mkTcTyVar (mkKindName u)
              tySuperKind  -- not sure this is right,
                            -- do we need kind vars for
                            -- coercions?
              (MetaTv TauTv r)

kind_var_occ :: OccName	-- Just one for all KindVars
			-- They may be jiggled by tidying
kind_var_occ = mkOccName tvName "k"
\end{code}

%************************************************************************
%*									*
		Pretty-printing
%*									*
%************************************************************************

\begin{code}
pprTcTyVarDetails :: TcTyVarDetails -> SDoc
-- For debugging
pprTcTyVarDetails (SkolemTv _)         = ptext (sLit "sk")
pprTcTyVarDetails (FlatSkol {})        = ptext (sLit "fsk")
pprTcTyVarDetails (MetaTv TauTv _)     = ptext (sLit "tau")
pprTcTyVarDetails (MetaTv TcsTv _)     = ptext (sLit "tcs")
pprTcTyVarDetails (MetaTv (SigTv _) _) = ptext (sLit "sig")

pprUserTypeCtxt :: UserTypeCtxt -> SDoc
pprUserTypeCtxt (FunSigCtxt n)  = ptext (sLit "the type signature for") <+> quotes (ppr n)
pprUserTypeCtxt ExprSigCtxt     = ptext (sLit "an expression type signature")
pprUserTypeCtxt (ConArgCtxt c)  = ptext (sLit "the type of the constructor") <+> quotes (ppr c)
pprUserTypeCtxt (TySynCtxt c)   = ptext (sLit "the RHS of the type synonym") <+> quotes (ppr c)
pprUserTypeCtxt GenPatCtxt      = ptext (sLit "the type pattern of a generic definition")
pprUserTypeCtxt ThBrackCtxt     = ptext (sLit "a Template Haskell quotation [t|...|]")
pprUserTypeCtxt LamPatSigCtxt   = ptext (sLit "a pattern type signature")
pprUserTypeCtxt BindPatSigCtxt  = ptext (sLit "a pattern type signature")
pprUserTypeCtxt ResSigCtxt      = ptext (sLit "a result type signature")
pprUserTypeCtxt (ForSigCtxt n)  = ptext (sLit "the foreign declaration for") <+> quotes (ppr n)
pprUserTypeCtxt DefaultDeclCtxt = ptext (sLit "a type in a `default' declaration")
pprUserTypeCtxt SpecInstCtxt    = ptext (sLit "a SPECIALISE instance pragma")

pprSkolTvBinding :: TcTyVar -> SDoc
-- Print info about the binding of a skolem tyvar, 
-- or nothing if we don't have anything useful to say
pprSkolTvBinding tv
  = ASSERT ( isTcTyVar tv )
    quotes (ppr tv) <+> ppr_details (tcTyVarDetails tv)
  where
    ppr_details (SkolemTv info)      = ppr_skol info
    ppr_details (FlatSkol {}) 	     = ptext (sLit "is a flattening type variable")
    ppr_details (MetaTv (SigTv n) _) = ptext (sLit "is bound by the type signature for")
                                       <+> quotes (ppr n)
    ppr_details (MetaTv _ _)         = ptext (sLit "is a meta type variable")

    ppr_skol UnkSkol	    = ptext (sLit "is an unknown type variable")	-- Unhelpful
    ppr_skol RuntimeUnkSkol = ptext (sLit "is an unknown runtime type")
    ppr_skol info           = sep [ptext (sLit "is a rigid type variable bound by"),
				   sep [pprSkolInfo info, 
					nest 2 (ptext (sLit "at") <+> ppr (getSrcLoc tv))]]
 
instance Outputable SkolemInfo where
  ppr = pprSkolInfo

pprSkolInfo :: SkolemInfo -> SDoc
-- Complete the sentence "is a rigid type variable bound by..."
pprSkolInfo (SigSkol ctxt)  = pprUserTypeCtxt ctxt
pprSkolInfo (IPSkol ips)    = ptext (sLit "the implicit-parameter bindings for")
                              <+> pprWithCommas ppr ips
pprSkolInfo (ClsSkol cls)   = ptext (sLit "the class declaration for") <+> quotes (ppr cls)
pprSkolInfo InstSkol        = ptext (sLit "the instance declaration")
pprSkolInfo FamInstSkol     = ptext (sLit "the family instance declaration")
pprSkolInfo (RuleSkol name) = ptext (sLit "the RULE") <+> doubleQuotes (ftext name)
pprSkolInfo ArrowSkol       = ptext (sLit "the arrow form")
pprSkolInfo (PatSkol dc _)  = sep [ ptext (sLit "a pattern with constructor")
                                    , ppr dc <+> dcolon <+> ppr (dataConUserType dc) ]
pprSkolInfo (GenSkol ty)    = sep [ ptext (sLit "the polymorphic type")
			    	  , quotes (ppr ty) ]

-- UnkSkol
-- For type variables the others are dealt with by pprSkolTvBinding.  
-- For Insts, these cases should not happen
pprSkolInfo UnkSkol        = WARN( True, text "pprSkolInfo: UnkSkol" ) ptext (sLit "UnkSkol")
pprSkolInfo RuntimeUnkSkol = WARN( True, text "pprSkolInfo: RuntimeUnkSkol" ) ptext (sLit "RuntimeUnkSkol")

instance Outputable MetaDetails where
  ppr Flexi         = ptext (sLit "Flexi")
  ppr (Indirect ty) = ptext (sLit "Indirect") <+> ppr ty
\end{code}


%************************************************************************
%*									*
\subsection{TidyType}
%*									*
%************************************************************************

\begin{code}
-- | This tidies up a type for printing in an error message, or in
-- an interface file.
-- 
-- It doesn't change the uniques at all, just the print names.
tidyTyVarBndr :: TidyEnv -> TyVar -> (TidyEnv, TyVar)
tidyTyVarBndr env@(tidy_env, subst) tyvar
  = case tidyOccName tidy_env (getOccName name) of
      (tidy', occ') -> ((tidy', subst'), tyvar'')
	where
	  subst' = extendVarEnv subst tyvar tyvar''
	  tyvar' = setTyVarName tyvar name'
	  name'  = tidyNameOcc name occ'
		-- Don't forget to tidy the kind for coercions!
	  tyvar'' | isCoVar tyvar = setTyVarKind tyvar' kind'
		  | otherwise	  = tyvar'
	  kind'  = tidyType env (tyVarKind tyvar)
  where
    name = tyVarName tyvar

---------------
tidyFreeTyVars :: TidyEnv -> TyVarSet -> TidyEnv
-- ^ Add the free 'TyVar's to the env in tidy form,
-- so that we can tidy the type they are free in
tidyFreeTyVars env tyvars = fst (tidyOpenTyVars env (varSetElems tyvars))

---------------
tidyOpenTyVars :: TidyEnv -> [TyVar] -> (TidyEnv, [TyVar])
tidyOpenTyVars env tyvars = mapAccumL tidyOpenTyVar env tyvars

---------------
tidyOpenTyVar :: TidyEnv -> TyVar -> (TidyEnv, TyVar)
-- ^ Treat a new 'TyVar' as a binder, and give it a fresh tidy name
-- using the environment if one has not already been allocated. See
-- also 'tidyTyVarBndr'
tidyOpenTyVar env@(_, subst) tyvar
  = case lookupVarEnv subst tyvar of
	Just tyvar' -> (env, tyvar')		-- Already substituted
	Nothing	    -> tidyTyVarBndr env tyvar	-- Treat it as a binder

---------------
tidyType :: TidyEnv -> Type -> Type
tidyType env@(_, subst) ty
  = go ty
  where
    go (TyVarTy tv)	    = case lookupVarEnv subst tv of
				Nothing  -> expand tv
				Just tv' -> expand tv'
    go (TyConApp tycon tys) = let args = map go tys
			      in args `seqList` TyConApp tycon args
    go (PredTy sty)	    = PredTy (tidyPred env sty)
    go (AppTy fun arg)	    = (AppTy $! (go fun)) $! (go arg)
    go (FunTy fun arg)	    = (FunTy $! (go fun)) $! (go arg)
    go (ForAllTy tv ty)	    = ForAllTy tvp $! (tidyType envp ty)
			      where
			        (envp, tvp) = tidyTyVarBndr env tv

    -- Expand FlatSkols, the skolems introduced by flattening process
    -- We don't want to show them in type error messages
    expand tv | isTcTyVar tv
              , FlatSkol ty <- tcTyVarDetails tv
              = go ty
              | otherwise
              = TyVarTy tv

---------------
tidyTypes :: TidyEnv -> [Type] -> [Type]
tidyTypes env tys = map (tidyType env) tys

---------------
tidyPred :: TidyEnv -> PredType -> PredType
tidyPred env (IParam n ty)     = IParam n (tidyType env ty)
tidyPred env (ClassP clas tys) = ClassP clas (tidyTypes env tys)
tidyPred env (EqPred ty1 ty2)  = EqPred (tidyType env ty1) (tidyType env ty2)

---------------
-- | Grabs the free type variables, tidies them
-- and then uses 'tidyType' to work over the type itself
tidyOpenType :: TidyEnv -> Type -> (TidyEnv, Type)
tidyOpenType env ty
  = (env', tidyType env' ty)
  where
    env' = tidyFreeTyVars env (tyVarsOfType ty)

---------------
tidyOpenTypes :: TidyEnv -> [Type] -> (TidyEnv, [Type])
tidyOpenTypes env tys = mapAccumL tidyOpenType env tys

---------------
-- | Calls 'tidyType' on a top-level type (i.e. with an empty tidying environment)
tidyTopType :: Type -> Type
tidyTopType ty = tidyType emptyTidyEnv ty

---------------
tidySkolemTyVar :: TidyEnv -> TcTyVar -> (TidyEnv, TcTyVar)
-- Tidy the type inside a GenSkol, preparatory to printing it
tidySkolemTyVar env tv
  = ASSERT( isTcTyVar tv && (isSkolemTyVar tv || isSigTyVar tv ) )
    (env1, mkTcTyVar (tyVarName tv) (tyVarKind tv) info1)
  where
    (env1, info1) = case tcTyVarDetails tv of
			SkolemTv info -> (env1, SkolemTv info')
				where
				  (env1, info') = tidy_skol_info env info
			info -> (env, info)

    tidy_skol_info env (GenSkol ty) = (env1, GenSkol ty1)
			    where
			      (env1, ty1)  = tidyOpenType env ty
    tidy_skol_info env info = (env, info)

---------------
tidyKind :: TidyEnv -> Kind -> (TidyEnv, Kind)
tidyKind env k = tidyOpenType env k
\end{code}


%************************************************************************
%*									*
		Predicates
%*									*
%************************************************************************

\begin{code}
isImmutableTyVar :: TyVar -> Bool

isImmutableTyVar tv
  | isTcTyVar tv = isSkolemTyVar tv
  | otherwise    = True

isTyConableTyVar, isSkolemTyVar, isOverlappableTyVar,
  isMetaTyVar :: TcTyVar -> Bool 

isTyConableTyVar tv	
	-- True of a meta-type variable that can be filled in 
	-- with a type constructor application; in particular,
	-- not a SigTv
  = ASSERT( isTcTyVar tv) 
    case tcTyVarDetails tv of
	MetaTv (SigTv _) _ -> False
	_                  -> True
	
isSkolemTyVar tv 
  = ASSERT2( isTcTyVar tv, ppr tv )
    case tcTyVarDetails tv of
	SkolemTv {} -> True
        FlatSkol {} -> True
 	MetaTv {}   -> False

-- isOverlappableTyVar has a unique purpose.
-- See Note [Binding when looking up instances] in InstEnv.
isOverlappableTyVar tv
  = ASSERT( isTcTyVar tv )
    case tcTyVarDetails tv of
        SkolemTv (PatSkol {})  -> True
        SkolemTv (InstSkol {}) -> True
        _                      -> False

isMetaTyVar tv 
  = ASSERT2( isTcTyVar tv, ppr tv )
    case tcTyVarDetails tv of
	MetaTv _ _ -> True
	_          -> False

isMetaTyVarTy :: TcType -> Bool
isMetaTyVarTy (TyVarTy tv) = isMetaTyVar tv
isMetaTyVarTy _            = False

isSigTyVar :: Var -> Bool
isSigTyVar tv 
  = ASSERT( isTcTyVar tv )
    case tcTyVarDetails tv of
	MetaTv (SigTv _) _ -> True
	_                  -> False

metaTvRef :: TyVar -> IORef MetaDetails
metaTvRef tv 
  = ASSERT2( isTcTyVar tv, ppr tv )
    case tcTyVarDetails tv of
	MetaTv _ ref -> ref
	_          -> pprPanic "metaTvRef" (ppr tv)

isFlexi, isIndirect :: MetaDetails -> Bool
isFlexi Flexi = True
isFlexi _     = False

isIndirect (Indirect _) = True
isIndirect _            = False

isRuntimeUnkSkol :: TyVar -> Bool
-- Called only in TcErrors; see Note [Runtime skolems] there
isRuntimeUnkSkol x | isTcTyVar x
  		   , SkolemTv RuntimeUnkSkol <- tcTyVarDetails x 
  		   = True
  		   | otherwise = False

isUnkSkol :: TyVar -> Bool
isUnkSkol x | isTcTyVar x
            , SkolemTv UnkSkol <- tcTyVarDetails x = True
            | otherwise = False
\end{code}


%************************************************************************
%*									*
\subsection{Tau, sigma and rho}
%*									*
%************************************************************************

\begin{code}
mkSigmaTy :: [TyVar] -> [PredType] -> Type -> Type
mkSigmaTy tyvars theta tau = mkForAllTys tyvars (mkPhiTy theta tau)

mkPhiTy :: [PredType] -> Type -> Type
mkPhiTy theta ty = foldr (\p r -> mkFunTy (mkPredTy p) r) ty theta
\end{code}

@isTauTy@ tests for nested for-alls.  It should not be called on a boxy type.

\begin{code}
isTauTy :: Type -> Bool
isTauTy ty | Just ty' <- tcView ty = isTauTy ty'
isTauTy (TyVarTy _)	  = True
isTauTy (TyConApp tc tys) = all isTauTy tys && isTauTyCon tc
isTauTy (AppTy a b)	  = isTauTy a && isTauTy b
isTauTy (FunTy a b)	  = isTauTy a && isTauTy b
isTauTy (PredTy _)	  = True		-- Don't look through source types
isTauTy _    		  = False


isTauTyCon :: TyCon -> Bool
-- Returns False for type synonyms whose expansion is a polytype
isTauTyCon tc 
  | isClosedSynTyCon tc = isTauTy (snd (synTyConDefn tc))
  | otherwise           = True

---------------
isRigidTy :: TcType -> Bool
-- A type is rigid if it has no meta type variables in it
isRigidTy ty = all isImmutableTyVar (varSetElems (tcTyVarsOfType ty))

isRefineableTy :: TcType -> (Bool,Bool)
-- A type should have type refinements applied to it if it has
-- free type variables, and they are all rigid
isRefineableTy ty = (null tc_tvs,  all isImmutableTyVar tc_tvs)
		    where
		      tc_tvs = varSetElems (tcTyVarsOfType ty)

isRefineablePred :: TcPredType -> Bool
isRefineablePred pred = not (null tc_tvs) && all isImmutableTyVar tc_tvs
		      where
		        tc_tvs = varSetElems (tcTyVarsOfPred pred)

---------------
getDFunTyKey :: Type -> OccName	-- Get some string from a type, to be used to 
				-- construct a dictionary function name
getDFunTyKey ty | Just ty' <- tcView ty = getDFunTyKey ty'
getDFunTyKey (TyVarTy tv)    = getOccName tv
getDFunTyKey (TyConApp tc _) = getOccName tc
getDFunTyKey (AppTy fun _)   = getDFunTyKey fun
getDFunTyKey (FunTy _ _)     = getOccName funTyCon
getDFunTyKey (ForAllTy _ t)  = getDFunTyKey t
getDFunTyKey ty		     = pprPanic "getDFunTyKey" (pprType ty)
-- PredTy shouldn't happen
\end{code}


%************************************************************************
%*									*
\subsection{Expanding and splitting}
%*									*
%************************************************************************

These tcSplit functions are like their non-Tc analogues, but
	a) they do not look through newtypes
	b) they do not look through PredTys

However, they are non-monadic and do not follow through mutable type
variables.  It's up to you to make sure this doesn't matter.

\begin{code}
tcSplitForAllTys :: Type -> ([TyVar], Type)
tcSplitForAllTys ty = split ty ty []
   where
     split orig_ty ty tvs | Just ty' <- tcView ty = split orig_ty ty' tvs
     split _ (ForAllTy tv ty) tvs 
       | not (isCoVar tv) = split ty ty (tv:tvs)
     split orig_ty _ tvs = (reverse tvs, orig_ty)

tcIsForAllTy :: Type -> Bool
tcIsForAllTy ty | Just ty' <- tcView ty = tcIsForAllTy ty'
tcIsForAllTy (ForAllTy tv _) = not (isCoVar tv)
tcIsForAllTy _               = False

tcSplitPredFunTy_maybe :: Type -> Maybe (PredType, Type)
-- Split off the first predicate argument from a type
tcSplitPredFunTy_maybe ty | Just ty' <- tcView ty = tcSplitPredFunTy_maybe ty'
tcSplitPredFunTy_maybe (ForAllTy tv ty)
  | isCoVar tv = Just (coVarPred tv, ty)
tcSplitPredFunTy_maybe (FunTy arg res)
  | Just p <- tcSplitPredTy_maybe arg = Just (p, res)
tcSplitPredFunTy_maybe _
  = Nothing

tcSplitPhiTy :: Type -> (ThetaType, Type)
tcSplitPhiTy ty
  = split ty []
  where
    split ty ts 
      = case tcSplitPredFunTy_maybe ty of
	  Just (pred, ty) -> split ty (pred:ts)
	  Nothing         -> (reverse ts, ty)

tcSplitSigmaTy :: Type -> ([TyVar], ThetaType, Type)
tcSplitSigmaTy ty = case tcSplitForAllTys ty of
			(tvs, rho) -> case tcSplitPhiTy rho of
					(theta, tau) -> (tvs, theta, tau)

-----------------------
tcDeepSplitSigmaTy_maybe
  :: TcSigmaType -> Maybe ([TcType], [TyVar], ThetaType, TcSigmaType)
-- Looks for a *non-trivial* quantified type, under zero or more function arrows
-- By "non-trivial" we mean either tyvars or constraints are non-empty

tcDeepSplitSigmaTy_maybe ty
  | Just (arg_ty, res_ty)           <- tcSplitFunTy_maybe ty
  , Just (arg_tys, tvs, theta, rho) <- tcDeepSplitSigmaTy_maybe res_ty
  = Just (arg_ty:arg_tys, tvs, theta, rho)

  | (tvs, theta, rho) <- tcSplitSigmaTy ty
  , not (null tvs && null theta)
  = Just ([], tvs, theta, rho)

  | otherwise = Nothing

-----------------------
tcTyConAppTyCon :: Type -> TyCon
tcTyConAppTyCon ty = case tcSplitTyConApp_maybe ty of
			Just (tc, _) -> tc
			Nothing	     -> pprPanic "tcTyConAppTyCon" (pprType ty)

tcTyConAppArgs :: Type -> [Type]
tcTyConAppArgs ty = case tcSplitTyConApp_maybe ty of
			Just (_, args) -> args
			Nothing	       -> pprPanic "tcTyConAppArgs" (pprType ty)

tcSplitTyConApp :: Type -> (TyCon, [Type])
tcSplitTyConApp ty = case tcSplitTyConApp_maybe ty of
			Just stuff -> stuff
			Nothing	   -> pprPanic "tcSplitTyConApp" (pprType ty)

tcSplitTyConApp_maybe :: Type -> Maybe (TyCon, [Type])
tcSplitTyConApp_maybe ty | Just ty' <- tcView ty = tcSplitTyConApp_maybe ty'
tcSplitTyConApp_maybe (TyConApp tc tys) = Just (tc, tys)
tcSplitTyConApp_maybe (FunTy arg res)   = Just (funTyCon, [arg,res])
	-- Newtypes are opaque, so they may be split
	-- However, predicates are not treated
	-- as tycon applications by the type checker
tcSplitTyConApp_maybe _                 = Nothing

-----------------------
tcSplitFunTys :: Type -> ([Type], Type)
tcSplitFunTys ty = case tcSplitFunTy_maybe ty of
			Nothing	       -> ([], ty)
			Just (arg,res) -> (arg:args, res')
				       where
					  (args,res') = tcSplitFunTys res

tcSplitFunTy_maybe :: Type -> Maybe (Type, Type)
tcSplitFunTy_maybe ty | Just ty' <- tcView ty           = tcSplitFunTy_maybe ty'
tcSplitFunTy_maybe (FunTy arg res) | not (isPredTy arg) = Just (arg, res)
tcSplitFunTy_maybe _                                    = Nothing
	-- Note the (not (isPredTy arg)) guard
	-- Consider	(?x::Int) => Bool
	-- We don't want to treat this as a function type!
	-- A concrete example is test tc230:
	--	f :: () -> (?p :: ()) => () -> ()
	--
	--	g = f () ()

tcSplitFunTysN
	:: TcRhoType 
	-> Arity		-- N: Number of desired args
	-> ([TcSigmaType], 	-- Arg types (N or fewer)
	    TcSigmaType)	-- The rest of the type

tcSplitFunTysN ty n_args
  | n_args == 0
  = ([], ty)
  | Just (arg,res) <- tcSplitFunTy_maybe ty
  = case tcSplitFunTysN res (n_args - 1) of
	(args, res) -> (arg:args, res)
  | otherwise
  = ([], ty)

tcSplitFunTy :: Type -> (Type, Type)
tcSplitFunTy  ty = expectJust "tcSplitFunTy" (tcSplitFunTy_maybe ty)

tcFunArgTy :: Type -> Type
tcFunArgTy    ty = fst (tcSplitFunTy ty)

tcFunResultTy :: Type -> Type
tcFunResultTy ty = snd (tcSplitFunTy ty)

-----------------------
tcSplitAppTy_maybe :: Type -> Maybe (Type, Type)
tcSplitAppTy_maybe ty | Just ty' <- tcView ty = tcSplitAppTy_maybe ty'
tcSplitAppTy_maybe ty = repSplitAppTy_maybe ty

tcSplitAppTy :: Type -> (Type, Type)
tcSplitAppTy ty = case tcSplitAppTy_maybe ty of
		    Just stuff -> stuff
		    Nothing    -> pprPanic "tcSplitAppTy" (pprType ty)

tcSplitAppTys :: Type -> (Type, [Type])
tcSplitAppTys ty
  = go ty []
  where
    go ty args = case tcSplitAppTy_maybe ty of
		   Just (ty', arg) -> go ty' (arg:args)
		   Nothing	   -> (ty,args)

-----------------------
tcGetTyVar_maybe :: Type -> Maybe TyVar
tcGetTyVar_maybe ty | Just ty' <- tcView ty = tcGetTyVar_maybe ty'
tcGetTyVar_maybe (TyVarTy tv)   = Just tv
tcGetTyVar_maybe _              = Nothing

tcGetTyVar :: String -> Type -> TyVar
tcGetTyVar msg ty = expectJust msg (tcGetTyVar_maybe ty)

tcIsTyVarTy :: Type -> Bool
tcIsTyVarTy ty = maybeToBool (tcGetTyVar_maybe ty)

-----------------------
tcSplitDFunTy :: Type -> ([TyVar], Class, [Type])
-- Split the type of a dictionary function
-- We don't use tcSplitSigmaTy,  because a DFun may (with NDP)
-- have non-Pred arguments, such as
--     df :: forall m. (forall b. Eq b => Eq (m b)) -> C m
tcSplitDFunTy ty 
  = case tcSplitForAllTys ty                 of { (tvs, rho)  ->
    case tcSplitDFunHead (drop_pred_tys rho) of { (clas, tys) -> 
    (tvs, clas, tys) }}
  where
    -- Discard the context of the dfun.  This can be a mix of
    -- coercion and class constraints; or (in the general NDP case)
    -- some other function argument
    drop_pred_tys ty | Just ty' <- tcView ty = drop_pred_tys ty'
    drop_pred_tys (ForAllTy tv ty) = ASSERT( isCoVar tv ) drop_pred_tys ty
    drop_pred_tys (FunTy _ ty)     = drop_pred_tys ty
    drop_pred_tys ty               = ty

tcSplitDFunHead :: Type -> (Class, [Type])
tcSplitDFunHead tau  
  = case tcSplitPredTy_maybe tau of 
	Just (ClassP clas tys) -> (clas, tys)
	_ -> pprPanic "tcSplitDFunHead" (ppr tau)

tcInstHeadTyNotSynonym :: Type -> Bool
-- Used in Haskell-98 mode, for the argument types of an instance head
-- These must not be type synonyms, but everywhere else type synonyms
-- are transparent, so we need a special function here
tcInstHeadTyNotSynonym ty
  = case ty of
        TyConApp tc _ -> not (isSynTyCon tc)
        _ -> True

tcInstHeadTyAppAllTyVars :: Type -> Bool
-- Used in Haskell-98 mode, for the argument types of an instance head
-- These must be a constructor applied to type variable arguments
tcInstHeadTyAppAllTyVars ty
  | Just ty' <- tcView ty       -- Look through synonyms
  = tcInstHeadTyAppAllTyVars ty'
  | otherwise
  = case ty of
	TyConApp _ tys  -> ok tys
	FunTy arg res   -> ok [arg, res]
	_               -> False
  where
	-- Check that all the types are type variables,
	-- and that each is distinct
    ok tys = equalLength tvs tys && hasNoDups tvs
	   where
	     tvs = mapCatMaybes get_tv tys

    get_tv (TyVarTy tv)  = Just tv	-- through synonyms
    get_tv _             = Nothing
\end{code}



%************************************************************************
%*									*
\subsection{Predicate types}
%*									*
%************************************************************************

\begin{code}
evVarPred :: EvVar -> PredType
evVarPred var
  = case tcSplitPredTy_maybe (varType var) of
      Just pred -> pred
      Nothing   -> pprPanic "evVarPred" (ppr var <+> ppr (varType var))

tcSplitPredTy_maybe :: Type -> Maybe PredType
   -- Returns Just for predicates only
tcSplitPredTy_maybe ty | Just ty' <- tcView ty = tcSplitPredTy_maybe ty'
tcSplitPredTy_maybe (PredTy p)    = Just p
tcSplitPredTy_maybe _             = Nothing

predTyUnique :: PredType -> Unique
predTyUnique (IParam n _)    = getUnique (ipNameName n)
predTyUnique (ClassP clas _) = getUnique clas
predTyUnique (EqPred a b)    = pprPanic "predTyUnique" (ppr (EqPred a b))
\end{code}


--------------------- Dictionary types ---------------------------------

\begin{code}
mkClassPred :: Class -> [Type] -> PredType
mkClassPred clas tys = ClassP clas tys

isClassPred :: PredType -> Bool
isClassPred (ClassP _ _) = True
isClassPred _            = False

isTyVarClassPred :: PredType -> Bool
isTyVarClassPred (ClassP _ tys) = all tcIsTyVarTy tys
isTyVarClassPred _              = False

getClassPredTys_maybe :: PredType -> Maybe (Class, [Type])
getClassPredTys_maybe (ClassP clas tys) = Just (clas, tys)
getClassPredTys_maybe _                 = Nothing

getClassPredTys :: PredType -> (Class, [Type])
getClassPredTys (ClassP clas tys) = (clas, tys)
getClassPredTys _ = panic "getClassPredTys"

mkDictTy :: Class -> [Type] -> Type
mkDictTy clas tys = mkPredTy (ClassP clas tys)

isDictLikeTy :: Type -> Bool
-- Note [Dictionary-like types]
isDictLikeTy ty | Just ty' <- tcView ty = isDictTy ty'
isDictLikeTy (PredTy p) = isClassPred p
isDictLikeTy (TyConApp tc tys) 
  | isTupleTyCon tc     = all isDictLikeTy tys
isDictLikeTy _          = False
\end{code}

Note [Dictionary-like types]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Being "dictionary-like" means either a dictionary type or a tuple thereof.
In GHC 6.10 we build implication constraints which construct such tuples,
and if we land up with a binding
    t :: (C [a], Eq [a])
    t = blah
then we want to treat t as cheap under "-fdicts-cheap" for example.
(Implication constraints are normally inlined, but sadly not if the
occurrence is itself inside an INLINE function!  Until we revise the 
handling of implication constraints, that is.)  This turned out to
be important in getting good arities in DPH code.  Example:

    class C a
    class D a where { foo :: a -> a }
    instance C a => D (Maybe a) where { foo x = x }

    bar :: (C a, C b) => a -> b -> (Maybe a, Maybe b)
    {-# INLINE bar #-}
    bar x y = (foo (Just x), foo (Just y))

Then 'bar' should jolly well have arity 4 (two dicts, two args), but
we ended up with something like
   bar = __inline_me__ (\d1,d2. let t :: (D (Maybe a), D (Maybe b)) = ...
                                in \x,y. <blah>)

This is all a bit ad-hoc; eg it relies on knowing that implication
constraints build tuples.

--------------------- Implicit parameters ---------------------------------

\begin{code}
mkIPPred :: IPName Name -> Type -> PredType
mkIPPred ip ty = IParam ip ty

isIPPred :: PredType -> Bool
isIPPred (IParam _ _) = True
isIPPred _            = False
\end{code}

--------------------- Equality predicates ---------------------------------
\begin{code}
substEqSpec :: TvSubst -> [(TyVar,Type)] -> [(TcType,TcType)]
substEqSpec subst eq_spec = [ (substTyVar subst tv, substTy subst ty)
			    | (tv,ty) <- eq_spec]
\end{code}


%************************************************************************
%*									*
\subsection{Predicates}
%*									*
%************************************************************************

isSigmaTy returns true of any qualified type.  It doesn't *necessarily* have 
any foralls.  E.g.
	f :: (?x::Int) => Int -> Int

\begin{code}
isSigmaTy :: Type -> Bool
isSigmaTy ty | Just ty' <- tcView ty = isSigmaTy ty'
isSigmaTy (ForAllTy _ _) = True
isSigmaTy (FunTy a _)    = isPredTy a
isSigmaTy _              = False

isOverloadedTy :: Type -> Bool
-- Yes for a type of a function that might require evidence-passing
-- Used only by bindLocalMethods
-- NB: be sure to check for type with an equality predicate; hence isCoVar
isOverloadedTy ty | Just ty' <- tcView ty = isOverloadedTy ty'
isOverloadedTy (ForAllTy tv ty) = isCoVar tv || isOverloadedTy ty
isOverloadedTy (FunTy a _)      = isPredTy a
isOverloadedTy _                = False

isPredTy :: Type -> Bool	-- Belongs in TcType because it does 
				-- not look through newtypes, or predtypes (of course)
isPredTy ty | Just ty' <- tcView ty = isPredTy ty'
isPredTy (PredTy _) = True
isPredTy _          = False
\end{code}

\begin{code}
isFloatTy, isDoubleTy, isIntegerTy, isIntTy, isWordTy, isBoolTy,
    isUnitTy, isCharTy :: Type -> Bool
isFloatTy      = is_tc floatTyConKey
isDoubleTy     = is_tc doubleTyConKey
isIntegerTy    = is_tc integerTyConKey
isIntTy        = is_tc intTyConKey
isWordTy       = is_tc wordTyConKey
isBoolTy       = is_tc boolTyConKey
isUnitTy       = is_tc unitTyConKey
isCharTy       = is_tc charTyConKey

isStringTy :: Type -> Bool
isStringTy ty
  = case tcSplitTyConApp_maybe ty of
      Just (tc, [arg_ty]) -> tc == listTyCon && isCharTy arg_ty
      _                   -> False

is_tc :: Unique -> Type -> Bool
-- Newtypes are opaque to this
is_tc uniq ty = case tcSplitTyConApp_maybe ty of
			Just (tc, _) -> uniq == getUnique tc
			Nothing	     -> False
\end{code}

\begin{code}
-- NB: Currently used in places where we have already expanded type synonyms;
--     hence no 'coreView'.  This could, however, be changed without breaking
--     any code.
isSynFamilyTyConApp :: TcTauType -> Bool
isSynFamilyTyConApp (TyConApp tc tys) = isSynFamilyTyCon tc && 
                                      length tys == tyConArity tc 
isSynFamilyTyConApp _other            = False
\end{code}


%************************************************************************
%*									*
\subsection{Misc}
%*									*
%************************************************************************

\begin{code}
deNoteType :: Type -> Type
-- Remove all *outermost* type synonyms and other notes
deNoteType ty | Just ty' <- tcView ty = deNoteType ty'
deNoteType ty = ty
\end{code}

\begin{code}
tcTyVarsOfType :: Type -> TcTyVarSet
-- Just the *TcTyVars* free in the type
-- (Types.tyVarsOfTypes finds all free TyVars)
tcTyVarsOfType (TyVarTy tv)	    = if isTcTyVar tv then unitVarSet tv
						      else emptyVarSet
tcTyVarsOfType (TyConApp _ tys)     = tcTyVarsOfTypes tys
tcTyVarsOfType (PredTy sty)	    = tcTyVarsOfPred sty
tcTyVarsOfType (FunTy arg res)	    = tcTyVarsOfType arg `unionVarSet` tcTyVarsOfType res
tcTyVarsOfType (AppTy fun arg)	    = tcTyVarsOfType fun `unionVarSet` tcTyVarsOfType arg
tcTyVarsOfType (ForAllTy tyvar ty)  = (tcTyVarsOfType ty `delVarSet` tyvar)
                                      `unionVarSet` tcTyVarsOfTyVar tyvar
	-- We do sometimes quantify over skolem TcTyVars

tcTyVarsOfTyVar :: TcTyVar -> TyVarSet
tcTyVarsOfTyVar tv | isCoVar tv = tcTyVarsOfType (tyVarKind tv)
                   | otherwise  = emptyVarSet

tcTyVarsOfTypes :: [Type] -> TyVarSet
tcTyVarsOfTypes tys = foldr (unionVarSet.tcTyVarsOfType) emptyVarSet tys

tcTyVarsOfPred :: PredType -> TyVarSet
tcTyVarsOfPred (IParam _ ty)  	= tcTyVarsOfType ty
tcTyVarsOfPred (ClassP _ tys) 	= tcTyVarsOfTypes tys
tcTyVarsOfPred (EqPred ty1 ty2) = tcTyVarsOfType ty1 `unionVarSet` tcTyVarsOfType ty2
\end{code}

Note [Silly type synonym]
~~~~~~~~~~~~~~~~~~~~~~~~~
Consider
	type T a = Int
What are the free tyvars of (T x)?  Empty, of course!  
Here's the example that Ralf Laemmel showed me:
	foo :: (forall a. C u a -> C u a) -> u
	mappend :: Monoid u => u -> u -> u

	bar :: Monoid u => u
	bar = foo (\t -> t `mappend` t)
We have to generalise at the arg to f, and we don't
want to capture the constraint (Monad (C u a)) because
it appears to mention a.  Pretty silly, but it was useful to him.

exactTyVarsOfType is used by the type checker to figure out exactly
which type variables are mentioned in a type.  It's also used in the
smart-app checking code --- see TcExpr.tcIdApp

On the other hand, consider a *top-level* definition
	f = (\x -> x) :: T a -> T a
If we don't abstract over 'a' it'll get fixed to GHC.Prim.Any, and then
if we have an application like (f "x") we get a confusing error message 
involving Any.  So the conclusion is this: when generalising
  - at top level use tyVarsOfType
  - in nested bindings use exactTyVarsOfType
See Trac #1813 for example.

\begin{code}
exactTyVarsOfType :: TcType -> TyVarSet
-- Find the free type variables (of any kind)
-- but *expand* type synonyms.  See Note [Silly type synonym] above.
exactTyVarsOfType ty
  = go ty
  where
    go ty | Just ty' <- tcView ty = go ty'	-- This is the key line
    go (TyVarTy tv)         	  = unitVarSet tv
    go (TyConApp _ tys)     	  = exactTyVarsOfTypes tys
    go (PredTy ty)	    	  = go_pred ty
    go (FunTy arg res)	    	  = go arg `unionVarSet` go res
    go (AppTy fun arg)	    	  = go fun `unionVarSet` go arg
    go (ForAllTy tyvar ty)  	  = delVarSet (go ty) tyvar
                                    `unionVarSet` go_tv tyvar

    go_pred (IParam _ ty)    = go ty
    go_pred (ClassP _ tys)   = exactTyVarsOfTypes tys
    go_pred (EqPred ty1 ty2) = go ty1 `unionVarSet` go ty2

    go_tv tyvar | isCoVar tyvar = go (tyVarKind tyvar)
                | otherwise     = emptyVarSet

exactTyVarsOfTypes :: [TcType] -> TyVarSet
exactTyVarsOfTypes tys = foldr (unionVarSet . exactTyVarsOfType) emptyVarSet tys
\end{code}

Find the free tycons and classes of a type.  This is used in the front
end of the compiler.

\begin{code}
tyClsNamesOfType :: Type -> NameSet
tyClsNamesOfType (TyVarTy _)		    = emptyNameSet
tyClsNamesOfType (TyConApp tycon tys)	    = unitNameSet (getName tycon) `unionNameSets` tyClsNamesOfTypes tys
tyClsNamesOfType (PredTy (IParam _ ty))     = tyClsNamesOfType ty
tyClsNamesOfType (PredTy (ClassP cl tys))   = unitNameSet (getName cl) `unionNameSets` tyClsNamesOfTypes tys
tyClsNamesOfType (PredTy (EqPred ty1 ty2))  = tyClsNamesOfType ty1 `unionNameSets` tyClsNamesOfType ty2
tyClsNamesOfType (FunTy arg res)	    = tyClsNamesOfType arg `unionNameSets` tyClsNamesOfType res
tyClsNamesOfType (AppTy fun arg)	    = tyClsNamesOfType fun `unionNameSets` tyClsNamesOfType arg
tyClsNamesOfType (ForAllTy _ ty)	    = tyClsNamesOfType ty

tyClsNamesOfTypes :: [Type] -> NameSet
tyClsNamesOfTypes tys = foldr (unionNameSets . tyClsNamesOfType) emptyNameSet tys

tyClsNamesOfDFunHead :: Type -> NameSet
-- Find the free type constructors and classes 
-- of the head of the dfun instance type
-- The 'dfun_head_type' is because of
--	instance Foo a => Baz T where ...
-- The decl is an orphan if Baz and T are both not locally defined,
--	even if Foo *is* locally defined
tyClsNamesOfDFunHead dfun_ty 
  = case tcSplitSigmaTy dfun_ty of
	(_, _, head_ty) -> tyClsNamesOfType head_ty
\end{code}


%************************************************************************
%*									*
\subsection[TysWiredIn-ext-type]{External types}
%*									*
%************************************************************************

The compiler's foreign function interface supports the passing of a
restricted set of types as arguments and results (the restricting factor
being the )

\begin{code}
tcSplitIOType_maybe :: Type -> Maybe (TyCon, Type, CoercionI)
-- (isIOType t) returns Just (IO,t',co)
--				if co : t ~ IO t'
--		returns Nothing otherwise
tcSplitIOType_maybe ty 
  = case tcSplitTyConApp_maybe ty of
	-- This split absolutely has to be a tcSplit, because we must
	-- see the IO type; and it's a newtype which is transparent to splitTyConApp.

	Just (io_tycon, [io_res_ty]) 
	   |  io_tycon `hasKey` ioTyConKey 
	   -> Just (io_tycon, io_res_ty, IdCo ty)

	Just (tc, tys)
	   | not (isRecursiveTyCon tc)
	   , Just (ty, co1) <- instNewTyCon_maybe tc tys
		  -- Newtypes that require a coercion are ok
	   -> case tcSplitIOType_maybe ty of
		Nothing		    -> Nothing
		Just (tc, ty', co2) -> Just (tc, ty', co1 `mkTransCoI` co2)

	_ -> Nothing

isFFITy :: Type -> Bool
-- True for any TyCon that can possibly be an arg or result of an FFI call
isFFITy ty = checkRepTyCon legalFFITyCon ty

isFFIArgumentTy :: DynFlags -> Safety -> Type -> Bool
-- Checks for valid argument type for a 'foreign import'
isFFIArgumentTy dflags safety ty 
   = checkRepTyCon (legalOutgoingTyCon dflags safety) ty

isFFIExternalTy :: Type -> Bool
-- Types that are allowed as arguments of a 'foreign export'
isFFIExternalTy ty = checkRepTyCon legalFEArgTyCon ty

isFFIImportResultTy :: DynFlags -> Type -> Bool
isFFIImportResultTy dflags ty 
  = checkRepTyCon (legalFIResultTyCon dflags) ty

isFFIExportResultTy :: Type -> Bool
isFFIExportResultTy ty = checkRepTyCon legalFEResultTyCon ty

isFFIDynArgumentTy :: Type -> Bool
-- The argument type of a foreign import dynamic must be Ptr, FunPtr, Addr,
-- or a newtype of either.
isFFIDynArgumentTy = checkRepTyConKey [ptrTyConKey, funPtrTyConKey]

isFFIDynResultTy :: Type -> Bool
-- The result type of a foreign export dynamic must be Ptr, FunPtr, Addr,
-- or a newtype of either.
isFFIDynResultTy = checkRepTyConKey [ptrTyConKey, funPtrTyConKey]

isFFILabelTy :: Type -> Bool
-- The type of a foreign label must be Ptr, FunPtr, Addr,
-- or a newtype of either.
isFFILabelTy = checkRepTyConKey [ptrTyConKey, funPtrTyConKey]

isFFIPrimArgumentTy :: DynFlags -> Type -> Bool
-- Checks for valid argument type for a 'foreign import prim'
-- Currently they must all be simple unlifted types.
isFFIPrimArgumentTy dflags ty
   = checkRepTyCon (legalFIPrimArgTyCon dflags) ty

isFFIPrimResultTy :: DynFlags -> Type -> Bool
-- Checks for valid result type for a 'foreign import prim'
-- Currently it must be an unlifted type, including unboxed tuples.
isFFIPrimResultTy dflags ty
   = checkRepTyCon (legalFIPrimResultTyCon dflags) ty

isFFIDotnetTy :: DynFlags -> Type -> Bool
isFFIDotnetTy dflags ty
  = checkRepTyCon (\ tc -> (legalFIResultTyCon dflags tc || 
			   isFFIDotnetObjTy ty || isStringTy ty)) ty
	-- NB: isStringTy used to look through newtypes, but
	--     it no longer does so.  May need to adjust isFFIDotNetTy
	--     if we do want to look through newtypes.

isFFIDotnetObjTy :: Type -> Bool
isFFIDotnetObjTy ty
  = checkRepTyCon check_tc t_ty
  where
   (_, t_ty) = tcSplitForAllTys ty
   check_tc tc = getName tc == objectTyConName

isFunPtrTy :: Type -> Bool
isFunPtrTy = checkRepTyConKey [funPtrTyConKey]

checkRepTyCon :: (TyCon -> Bool) -> Type -> Bool
-- Look through newtypes, but *not* foralls
-- Should work even for recursive newtypes
-- eg Manuel had:	newtype T = MkT (Ptr T)
checkRepTyCon check_tc ty
  = go [] ty
  where
    go rec_nts ty
      | Just (tc,tys) <- splitTyConApp_maybe ty
      = case carefullySplitNewType_maybe rec_nts tc tys of
      	   Just (rec_nts', ty') -> go rec_nts' ty'
	   Nothing	   	-> check_tc tc
      | otherwise
      = False

checkRepTyConKey :: [Unique] -> Type -> Bool
-- Like checkRepTyCon, but just looks at the TyCon key
checkRepTyConKey keys
  = checkRepTyCon (\tc -> tyConUnique tc `elem` keys)
\end{code}

----------------------------------------------
These chaps do the work; they are not exported
----------------------------------------------

\begin{code}
legalFEArgTyCon :: TyCon -> Bool
legalFEArgTyCon tc
  -- It's illegal to make foreign exports that take unboxed
  -- arguments.  The RTS API currently can't invoke such things.  --SDM 7/2000
  = boxedMarshalableTyCon tc

legalFIResultTyCon :: DynFlags -> TyCon -> Bool
legalFIResultTyCon dflags tc
  | tc == unitTyCon         = True
  | otherwise	            = marshalableTyCon dflags tc

legalFEResultTyCon :: TyCon -> Bool
legalFEResultTyCon tc
  | tc == unitTyCon         = True
  | otherwise               = boxedMarshalableTyCon tc

legalOutgoingTyCon :: DynFlags -> Safety -> TyCon -> Bool
-- Checks validity of types going from Haskell -> external world
legalOutgoingTyCon dflags _ tc
  = marshalableTyCon dflags tc

legalFFITyCon :: TyCon -> Bool
-- True for any TyCon that can possibly be an arg or result of an FFI call
legalFFITyCon tc
  = isUnLiftedTyCon tc || boxedMarshalableTyCon tc || tc == unitTyCon

marshalableTyCon :: DynFlags -> TyCon -> Bool
marshalableTyCon dflags tc
  =  (xopt Opt_UnliftedFFITypes dflags 
      && isUnLiftedTyCon tc
      && not (isUnboxedTupleTyCon tc)
      && case tyConPrimRep tc of	-- Note [Marshalling VoidRep]
	   VoidRep -> False
	   _       -> True)
  || boxedMarshalableTyCon tc

boxedMarshalableTyCon :: TyCon -> Bool
boxedMarshalableTyCon tc
   = getUnique tc `elem` [ intTyConKey, int8TyConKey, int16TyConKey
			 , int32TyConKey, int64TyConKey
			 , wordTyConKey, word8TyConKey, word16TyConKey
			 , word32TyConKey, word64TyConKey
			 , floatTyConKey, doubleTyConKey
			 , ptrTyConKey, funPtrTyConKey
			 , charTyConKey
			 , stablePtrTyConKey
			 , boolTyConKey
			 ]

legalFIPrimArgTyCon :: DynFlags -> TyCon -> Bool
-- Check args of 'foreign import prim', only allow simple unlifted types.
-- Strictly speaking it is unnecessary to ban unboxed tuples here since
-- currently they're of the wrong kind to use in function args anyway.
legalFIPrimArgTyCon dflags tc
  = xopt Opt_UnliftedFFITypes dflags
    && isUnLiftedTyCon tc
    && not (isUnboxedTupleTyCon tc)

legalFIPrimResultTyCon :: DynFlags -> TyCon -> Bool
-- Check result type of 'foreign import prim'. Allow simple unlifted
-- types and also unboxed tuple result types '... -> (# , , #)'
legalFIPrimResultTyCon dflags tc
  = xopt Opt_UnliftedFFITypes dflags
    && isUnLiftedTyCon tc
    && (isUnboxedTupleTyCon tc
        || case tyConPrimRep tc of	-- Note [Marshalling VoidRep]
	   VoidRep -> False
	   _       -> True)
\end{code}

Note [Marshalling VoidRep]
~~~~~~~~~~~~~~~~~~~~~~~~~~
We don't treat State# (whose PrimRep is VoidRep) as marshalable.
In turn that means you can't write
	foreign import foo :: Int -> State# RealWorld

Reason: the back end falls over with panic "primRepHint:VoidRep";
	and there is no compelling reason to permit it

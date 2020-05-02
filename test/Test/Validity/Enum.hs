{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
module Test.Validity.Enum where

import           Data.WordString32               as WS

import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Arbitrary       as ABS
import           Data.Typeable
import           Test.Hspec
import           Test.Hspec.QuickCheck           (prop)
import           Test.QuickCheck
import           Test.QuickCheck.Arbitrary
import           Test.QuickCheck.Gen
import           Test.Validity
import           Test.Validity.Arbitrary
import           Test.Validity.Eq
import           Test.Validity.Functions.Inverse
import           Test.Validity.Monoid
import           Test.Validity.Ord
import           Test.Validity.Utils

enumSpec :: forall    a
         . (Arbitrary a
           ,Typeable  a
           ,Enum      a
           ,Show      a
           ,Eq        a
           ) => Spec
enumSpec = enumSpecOnGen (arbitrary :: Gen a)
                         "arbitrary"
                         (shrink :: a -> [a])

enumSpecOnGen :: (Enum     a
                 ,Eq       a
                 ,Show     a
                 ,Typeable a)
              =>  Gen a  -- generator
              ->  String -- generator name
              -> (a -> [a]) -- shrinker
              ->  Spec
enumSpecOnGen (gen :: Gen a) genName shrinker =
    describe ("Enum " <> name <> " on " <> genName) $ do
      prop "toEnum . fromEnum == id" $
        inverseFunctionsOnGen fromEnum (toEnum :: Int -> a) gen shrinker
        --(toEnum :: Int -> a) fromEnum
  where
    name = nameOf @a

--toEnumInvertsFromEnumOnGen :: _
toEnumInvertsFromEnumOnGen gen = do
  x <- gen
  toEnum (fromEnum x) `shouldBe` x

-- | Word32 strings for convenient handling
--   Just like ByteString, but with 32-bit each
--
--   Note that we only use methods from fast-parsing instance of xeno and XML Typelift
--   NOTE: put paper reference here when it is published
module Data.WordString32 (
    WordString -- opaque for safety
  , fromBS
  , toBS
  , null
  , index
  , drop
  , take
  , empty
  , length
  , append -- Use Semigroup.<>
  ) where

import           Control.Exception        (assert)
import qualified Data.ByteString          as BS (empty, take)
import qualified Data.ByteString.Internal as BS
import           Data.Function            (on)
import           Data.Word
import           Debug.Trace
import           Foreign.C.Types          (CSize (..))
import           Foreign.ForeignPtr       (ForeignPtr, castForeignPtr,
                                           withForeignPtr)
import           Foreign.Ptr              (Ptr, nullPtr, plusPtr)
import           Foreign.Storable
import           GHC.ForeignPtr           (mallocPlainForeignPtrBytes)
import           Prelude                  hiding (drop, length, null, take)
import           System.IO.Unsafe         (unsafeDupablePerformIO)

-- | Opaque array of 32-bit words
data WordString = WS {
    wsPtr    :: ForeignPtr Word32
  , wsOffset :: Int
  , wsLen    :: Int
  }

instance Show WordString where
  show = show . BS.take 16 . toBS

-- | Assume these instances will not be used often.
instance Eq WordString where
  (==) = (==) `on` toBS

instance Ord WordString where
  compare = compare `on` toBS

-- TODO: make a direct conduit?
{-# INLINE fromBS #-}
fromBS :: BS.ByteString -> WordString
fromBS (BS.PS wsPtr bsOffset bsLen) =
    if bsOffset `mod` 4 /= 0
      then error $ "ByteString offset must be divisible by 4 for Data.WordString32.fromBS, is: " <> show bsOffset
      else
        if bsLen `mod` 4 /= 0
          then error $ "ByteString length must be divisible by 4 for Data.WordString32.fromBS, is: " <> show bsLen
          else WS (castForeignPtr wsPtr) wsOffset wsLen
  where
    wsOffset = bsOffset `div` 4
    wsLen    = bsLen    `div` 4

{-# INLINE toBS #-}
toBS :: WordString -> BS.ByteString
toBS (WS wsPtr wsOffset wsLen) = BS.PS (castForeignPtr wsPtr) (wsOffset*4) (wsLen*4)

{-# INLINE index #-}
index :: WordString -> Int -> Word32
index  _                        i | i < 0 = error "index cannot be negative"
index (WS wsPtr wsOffset wsLen) i =
    assert (offset < wsLen) $
    unsafeDupablePerformIO  $
    withForeignPtr wsPtr    $
      (`peekElemOff` offset)
  where
    offset = wsOffset + i

{-# INLINE null #-}
null :: WordString -> Bool
null (WS wsPtr wsOffset wsLen) = wsOffset == wsLen

{-# INLINE drop #-}
drop :: Int -> WordString -> WordString
drop i  _                | i < 0 = error "Dropping negative number of bytes"
drop i (WS wsPtr wsOffset wsLen) =
    assert (newWsOffset<wsLen)   $
      WS wsPtr (min newWsOffset wsLen) wsLen
  where
    newWsOffset = wsOffset+i

{-# INLINE take #-}
take :: Int -> WordString -> WordString
take i (WS wsPtr wsOffset wsLen) =
        WS wsPtr wsOffset $ min wsLen $ wsOffset+i

empty :: WordString
empty  = fromBS $ BS.empty

length :: WordString -> Int
length (WS _ ofs len) = len-ofs

instance Monoid WordString where
  mempty = empty

instance Semigroup WordString where
  (<>) = append

foreign import ccall unsafe "string.h memcpy" c_memcpy
    :: Ptr Word32 -> Ptr Word32 -> CSize -> IO (Ptr Word32)

memcpy :: Ptr Word32 -> Ptr Word32 -> Int -> IO ()
memcpy p q s = do
  c_memcpy p q $ fromIntegral s*4
  return ()

append a b | null b = a
append a b | null a = b
append (WS aPtr aOffset aLen)
       (WS bPtr bOffset bLen) = trace "<append here>" $ unsafeDupablePerformIO $ do
    newPtr <- mallocPlainForeignPtrBytes totalLen
    withForeignPtr newPtr $ \destPtrA -> do
      withForeignPtr aPtr $ \srcPtrA ->
        memcpy destPtrA (srcPtrA `plusPtr` aOffset) aLen
      let destPtrB = destPtrA `plusPtr` aLen
      withForeignPtr bPtr $ \srcPtrB ->
        memcpy destPtrB (srcPtrB `plusPtr` bOffset) bLen
    return $ WS (castForeignPtr newPtr) 0 totalLen
  where
    totalLen = aLen+bLen

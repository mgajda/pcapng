{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE StrictData      #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Pcap.Ng where
-- * This module provides a Pcap conduit
--   without using libpcap per set.
--   It sticks to the same types, but allows reading any stream of packets
--   not necessarily from libpcap, file or live source.

import           Conduit
import           Control.Exception         (assert)
import           Control.Lens
import           Control.Lens.TH
import qualified Data.ByteString.Char8     as BS
import           Data.Conduit.Cereal       (conduitGet2)
import           Data.Function
import           Data.Serialize
import           Data.Word
import qualified Data.WordString32         as WS
import qualified Data.WordString32.Conduit as WSC
import           GHC.Generics

import           Network.Pcap.NG.BlockType

import           Debug.Trace               (trace)

data Block = Block {
    _blockType :: BlockType
  , _blockBody :: BS.ByteString
  } deriving (Eq, Show, Generic)

makeLenses ''Block

instance Serialize Block where
  get = do
    blockType <- get
    blockLen  <- getWord32le
    let bodyLen = blockLen-12
    body      <- getBytes $ fromEnum bodyLen
    blockLen2 <- getWord32le
    if blockLen == blockLen2
      then pure $ Block blockType body
      else fail $ concat [
               "Inconsistent heading and trailing block lengths: "
             , show blockLen, " /= ", show blockLen2]
  put (Block bt body) = do
      put bt
      put totalLength
      putByteString paddedBody
      put totalLength
    where
      paddingLength = (4 - (BS.length body `mod` 4)) `mod` 4
      paddedBody    =  body <> BS.replicate paddingLength '\0'
      totalLength   =  12   +  BS.length paddedBody

pcapNgConduit :: MonadThrow m => ConduitT BS.ByteString Block m ()
pcapNgConduit  = conduitGet2 get

pcapNgConduit2 :: MonadFail m => ConduitT WS.WordString Block m ()
pcapNgConduit2 = WSC.atLeast  12 -- PcapNG files are expected to be word aligned, with 12 minimum block size
              .| blockConduit LittleEndian -- SHB in the beginning should fix endianness anyway

-- TODO: use CAF
sameEndianness  = LittleEndian
otherEndianness = BigEndian

-- FIXME: how to ensure unrolling on endianness?
blockConduit :: Monad m
             => Endianness
             -> ConduitT WS.WordString Block m ()
blockConduit endianness = awaitForever $ \dta -> do
    if dta `WS.index` 0 == 0x0A0D0D0A
       then do -- Section header block, palindromic identification
          -- identify endianness from magic number
          let newEndianness | dta `WS.index` 2 == 0x1A2B3C4D = trace "same endianness"  sameEndianness  -- same endianness as the machine
                            | dta `WS.index` 2 == 0x4D3C2B1A = trace "other endianness" otherEndianness -- opposite endianness on magic
                            | otherwise                      = error $ "Cannot recover endianness from: " <> show (dta `WS.index` 2)
          decodeBlock  newEndianness dta
          blockConduit newEndianness
       else decodeBlock endianness dta

{-# INLINE decodeBlock #-}
decodeBlock endianness dta =
  assert (headingLen >= 12) $
  assert (headingLen == trailingLen) $ do
    yield Block { _blockType = toEnum $ fromEnum $ swapper endianness $ dta `WS.index` 0
                , _blockBody = WS.toBS body
                }
    trace ("Block len is " <> show (dta `WS.index` 1) <> " after swap " <> show (swapper endianness (dta `WS.index` 1))
         <> "data" <> show dta
         <> "rest" <> show rest) $
      leftover rest
  where
    headingLen  = fromIntegral $ swapper endianness $ dta `WS.index` 3
    bodyLen     = headingLen - 12
    body        = WS.take (bodyLen `div` 4)
                $ WS.drop 2                        dta
    rest        = WS.drop (headingLen `div` 4) dta
    trailingLen = fromIntegral $ swapper endianness $ dta `WS.index` (headingLen - 1)


swapper endianness | sameEndianness == endianness = id
swapper endianness = byteSwap32

data Endianness =
    LittleEndian
  | BigEndian
  deriving (Eq, Show, Read, Enum, Bounded)

{-
data Pkt = Pkt {
    _hdr     :: PktHdr
  , _content :: BS.ByteString
  }

data PktHdr = PktHdr {
    _epochSeconds  :: Word32
  , _nanoSeconds   :: Word32
  , _captureLength :: Word32
  , _wireLength    :: Word32
  }

$(makeLenses ''PktHdr)

data PcapFormat = PcapFormat {
    littleEndian :: Endianness
  , version      :: FormatVersion
  } deriving (Eq, Show, Read, Enum, Bounded)

$(makeLenses ''PcapFormat)

data FormatVersion =
    Pcap
  | PcapNG
  deriving (Eq, Show, Read, Enum, Bounded)

magicNumber :: FormatVersion -> Word32
magicNumber  = undefined

readFormat :: Conduit Void BS.ByteString m ()
           -> m PcapFormat

pktConduit :: PcapFormat -> Conduit BS.ByteString Pkt ()
pktConduit  = return ()
 -}

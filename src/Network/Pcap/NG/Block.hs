{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE StrictData      #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Pcap.NG.Block(Block(..)
                            ,blockType
                            ,blockEndianness
                            ,blockBody
                            ,blockConduit) where
-- * This module provides a PcapNG conduit
--   for undifferentiated, undecoded PcapNG blocks
--   without using libpcap per set.
--   It sticks to the same types, but allows reading any stream of packets
--   not necessarily from libpcap, file or live source.

import           Conduit
import           Control.Exception          (assert)
import           Control.Lens
import           Control.Lens.TH
import           Control.Monad              (when)
import qualified Data.ByteString.Char8      as BS
import qualified Data.WordString32          as WS
import qualified Data.WordString32.Conduit  as WSC
import           GHC.Generics

import           Network.Pcap.NG.BlockType
import           Network.Pcap.NG.Endianness

import           Debug.Trace                (trace)

data Block = Block {
    _blockType       :: BlockType
  , _blockEndianness :: Endianness
  , _blockBody       :: BS.ByteString
  } deriving (Eq, Show, Generic)

makeLenses ''Block

blockConduit :: MonadFail m => ConduitT WS.WordString Block m ()
blockConduit  =  WSC.atLeast  12 -- PcapNG files are expected to be word aligned, with 12 minimum block size
              .| blockConduitWithEndianness sameEndianness -- SHB in the beginning should fix endianness anyway

-- TODO: how to ensure unrolling on endianness?
blockConduitWithEndianness ::
     Monad m
  => Endianness
  -> ConduitT WS.WordString Block m ()
blockConduitWithEndianness endianness =
  awaitForever $ \dta -> do
    if dta `WS.index` 0 == 0x0A0D0D0A
       then do -- Section header block, palindromic identification
          -- identify endianness from magic number
          let newEndianness | dta `WS.index` 2 == 0x1A2B3C4D = trace "same endianness"  sameEndianness  -- same endianness as the machine
                            | dta `WS.index` 2 == 0x4D3C2B1A = trace "other endianness" otherEndianness -- opposite endianness on magic
                            | otherwise                      = error $ "Cannot recover endianness from: " <> show (dta `WS.index` 2)
          decodeBlock                newEndianness dta
          blockConduitWithEndianness newEndianness
       else decodeBlock endianness dta

{-# INLINE decodeBlock #-}
decodeBlock :: Monad m
            => Endianness
            ->          WS.WordString
            -> ConduitT WS.WordString Block m ()
decodeBlock endianness dta =
  {-trace ("Block type " <> show decodedBlockType
       <> " len is " <> show headingLen <> " after swap " <> show (swapper endianness (dta `WS.index` 1))
       <> " data " <> show dta
       <> " rest " <> show rest) $-}
  assert (headingWords > 3) $
  assert (bodyWords  >= 0)  $
  assert (headingLen >= 12) $
  assert (headingLen == trailingLen) $ do
    yield Block { _blockType       = decodedBlockType
                , _blockEndianness = endianness
                , _blockBody       = WS.toBS body
                }
    when (WS.length rest > 0) $ leftover rest
  where
    decodedBlockType = toEnum $ fromEnum
                     $ swapper endianness
                     $ dta `WS.index` 0
    headingWords = headingLen `div` 4
    headingLen  = fromIntegral
                $ swapper endianness
                $ dta `WS.index` 1
    bodyLen     = headingLen - 12
    bodyWords   = bodyLen `div` 4
    body        = WS.take bodyWords
                $ WS.drop 2            dta
    rest        = WS.drop headingWords dta
    trailingLen = fromIntegral
                $ swapper endianness
                $ dta `WS.index` (headingLen - 1)

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

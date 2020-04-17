{-# LANGUAGE StrictData      #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Pcap.Ng where
-- * This module provides a Pcap conduit
--   without using libpcap per set.
--   It sticks to the same types, but allows reading any stream of packets
--   not necessarily from libpcap, file or live source.

import           Conduit
import           Control.Lens
import           Control.Lens.TH
import qualified Data.ByteString.Char8 as BS
import           Data.Function
import           Data.Word
import           Data.Serialize

import           Network.Pcap.NG.BlockType

data Block = Block {
    _blockType        :: BlockType
  , _blockBody        :: BS.ByteString
  }

instance Serialize Block where
  get = do
    blockType <- get
    blockLen  <- get
    let bodyLen = blockLen-12
    body      <- getBytes bodyLen
    blockLen2 <- get
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

data Endianness =
    LittleEndian
  | BigEndian
  deriving (Eq, Show, Read, Enum, Bounded)

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

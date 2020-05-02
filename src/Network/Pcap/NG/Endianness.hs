{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData    #-}
module Network.Pcap.NG.Endianness where
-- * This module provides a PcapNG conduit
--   for undifferentiated, undecoded PcapNG blocks
--   without using libpcap per set.
--   It sticks to the same types, but allows reading any stream of packets
--   not necessarily from libpcap, file or live source.

import           Data.Word
import           GHC.Generics

-- | Big or little endian?
data Endianness =
    LittleEndian
  | BigEndian
  deriving (Eq, Show, Read, Enum, Bounded, Generic)

-- TODO: use CAF
sameEndianness, otherEndianness :: Endianness
sameEndianness  = LittleEndian
otherEndianness = BigEndian

-- | Swap bytes from given endianness
--   to local byte order.
swapper :: Endianness -> Word32 -> Word32
swapper endianness
      | sameEndianness == endianness = id
swapper _                            = byteSwap32

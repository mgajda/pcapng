{-# LANGUAGE StrictData      #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Pcap.NG.BlockType(
    BlockType(..)
  , encodeBlockType
  , decodeBlockType
  , knownBlockTypes
  ) where
-- * This module provides a Pcap conduit
--   without using libpcap per set.
--   It sticks to the same types, but allows reading any stream of packets
--   not necessarily from libpcap, file or live source.

import qualified Data.ByteString.Char8 as BS
import           Data.Function
import           Data.Word
import           Data.Serialize

-- | PCAP-NG block type
--
--   See: file:///home/m/src/pcapng/draft-tuexen-opsawg-pcapng.html#rfc.section.11.1
data BlockType =
    IfDesc
  | Packet
  | SimplePacket -- obsolete
  | NameResolution
  | IfStats
  | EnhancedPacket
  | IRIGTimestamp
  | EncapsulationInfo
  | SystemDJournal
  | DecryptionSecrets
  | HoneMachInfo
  | HoneConnEvent
  | SysdigMachInfo
  | SysdigProcInfo { version :: Int }
  | SysdigFDList
  | SysdigEvent
  | SysdigIfList
  | SysdigEventWithFlags
  | SysdigUserList
  | Custom { copyBlock :: Bool}
  | SectionHeader
  -- Special block type codes
  | Reserved   Word32
  | Corruption Word32
  | LocalUse   Word32
  deriving (Show, Read)

instance Eq BlockType where
  (==) = (==) `on` encodeBlockType

instance Ord BlockType where
  compare = compare `on` encodeBlockType

instance Enum BlockType where
  fromEnum = fromEnum . encodeBlockType
  toEnum   = decodeBlockType . toEnum

decodeBlockType  0x00000000  = Reserved 0x00000000
decodeBlockType  0x00000001  = IfDesc
decodeBlockType  0x00000002  = Packet
decodeBlockType  0x00000003  = SimplePacket
decodeBlockType  0x00000004  = NameResolution
decodeBlockType  0x00000005  = IfStats
decodeBlockType  0x00000006  = EnhancedPacket
decodeBlockType  0x00000007  = IRIGTimestamp
decodeBlockType  0x00000008  = EncapsulationInfo
decodeBlockType  0x00000009  = SystemDJournal
decodeBlockType  0x0000000A  = DecryptionSecrets
decodeBlockType  0x00000101  = HoneMachInfo
decodeBlockType  0x00000102  = HoneConnEvent
decodeBlockType  0x00000201  = SysdigMachInfo
decodeBlockType  0x00000202  = SysdigProcInfo 1
decodeBlockType  0x00000203  = SysdigFDList
decodeBlockType  0x00000204  = SysdigEvent
decodeBlockType  0x00000205  = SysdigIfList
decodeBlockType  0x00000206  = SysdigUserList
decodeBlockType  0x00000207  = SysdigProcInfo 2
decodeBlockType  0x00000208  = SysdigEventWithFlags
decodeBlockType  0x00000209  = SysdigProcInfo 3
decodeBlockType  0x00000210  = SysdigProcInfo 4
decodeBlockType  0x00000211  = SysdigProcInfo 5
decodeBlockType  0x00000212  = SysdigProcInfo 6
decodeBlockType  0x00000213  = SysdigProcInfo 7
decodeBlockType  0x00000BAD  = Custom True
decodeBlockType  0x40000BAD  = Custom False
decodeBlockType  0x0A0D0D0A  = SectionHeader
decodeBlockType  a | a >= 0x0A0D0A00
             && a <= 0x0A0D0AFF = Corruption a
decodeBlockType  a | a >= 0x000A0D0A
             && a <= 0xFF0A0D0A = Corruption a
decodeBlockType  a | a >= 0x000A0D0D
             && a <= 0xFF0A0D0D = Corruption a
decodeBlockType  a | a >= 0x0D0D0A00
             && a <= 0x0D0D0AFF = Corruption a
decodeBlockType  a | a >= 0x80000000
             && a <= 0xFFFFFFFF = LocalUse a

encodeBlockType :: BlockType -> Word32
encodeBlockType (Corruption       c) = c
encodeBlockType (Reserved         c) = c
encodeBlockType (LocalUse         c) = c
encodeBlockType IfDesc               = 0x00000001
encodeBlockType Packet               = 0x00000002
encodeBlockType SimplePacket         = 0x00000003
encodeBlockType NameResolution       = 0x00000004
encodeBlockType IfStats              = 0x00000005
encodeBlockType EnhancedPacket       = 0x00000006
encodeBlockType IRIGTimestamp        = 0x00000007
encodeBlockType EncapsulationInfo    = 0x00000008
encodeBlockType SystemDJournal       = 0x00000009
encodeBlockType DecryptionSecrets    = 0x0000000A
encodeBlockType HoneMachInfo         = 0x00000101
encodeBlockType HoneConnEvent        = 0x00000102
encodeBlockType SysdigMachInfo       = 0x00000201
encodeBlockType (SysdigProcInfo 1)   = 0x00000202
encodeBlockType SysdigFDList         = 0x00000203
encodeBlockType SysdigEvent          = 0x00000204
encodeBlockType SysdigIfList         = 0x00000205
encodeBlockType SysdigUserList       = 0x00000206
encodeBlockType (SysdigProcInfo 2)   = 0x00000207
encodeBlockType SysdigEventWithFlags = 0x00000208
encodeBlockType (SysdigProcInfo 3)    = 0x00000209
encodeBlockType (SysdigProcInfo 4)    = 0x00000210
encodeBlockType (SysdigProcInfo 5)    = 0x00000211
encodeBlockType (SysdigProcInfo 6)    = 0x00000212
encodeBlockType (SysdigProcInfo 7)    = 0x00000213
encodeBlockType (Custom True )        = 0x00000BAD
encodeBlockType (Custom False)        = 0x40000BAD
encodeBlockType SectionHeader         = 0x0A0D0D0A
encodeBlockType other                 = error $ "Error in block type: " <> show other

knownBlockTypes = [SectionHeader, IfDesc .. EnhancedPacket]

instance Serialize BlockType where
  get = decodeBlockType <$> get
  put = put . encodeBlockType

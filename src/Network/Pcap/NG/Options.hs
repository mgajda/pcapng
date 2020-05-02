{-# LANGUAGE BinaryLiterals     #-}
{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE GADTs              #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE RankNTypes         #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StrictData         #-}
module Network.Pcap.NG.Options where

import           Control.Exception          (assert)
import           Data.Bits                  (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString            as BS
import           Data.Proxy
import           Data.Text                  (Text)
import qualified Data.Text                  as Text
import qualified Data.Text.Encoding         as Text (decodeUtf8)
import           Data.Word

import qualified Data.WordString32          as WS
import           Network.Pcap.NG.BlockType
import           Network.Pcap.NG.Endianness

{-
Quote from pcap-ng spec:
1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Option Code              |         Option Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                       Option Value                            /
/              variable length, padded to 32 bits               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                 . . . other options . . .                     /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Option Code == opt_endofopt |   Option Length == 0          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 -}

data Option a where
  Option :: { optionCode  :: OptionCode a
            , optionValue :: WS.WordString
            } -> Option a
  Comment :: { commentString :: Text }
          -> Option a
  CustomString :: {
      customString :: Text
    , customCopy   :: Bool
    , customPEN    :: Word32
    } -> Option a
  CustomBinary :: {
      customBinary :: WS.WordString
    , customCopy   :: Bool
    , customPEN    :: Word32
    } -> Option a
  SHBHardware :: { shbHardware :: Text } -> Option SectionHeader
  SHBOS       :: { shbOsString :: Text } -> Option SectionHeader
  SHBUserAppl :: { shbUserAppl :: Text } -> Option SectionHeader
  EPBFlags    :: { epbInboundOutbound :: InboundOutbound
                 , epbReceptionType   :: ReceptionType
                 , epbFCSLength       :: Word8 -- actually 4 bits
                 , epbLinkLayerErrors :: Word16
                 }
    -> Option EnhancedPacket
  EPBHash     :: { epbHash     :: WS.WordString }
    -> Option EnhancedPacket -- TODO: check if length is in words?
  EPBDropCount :: { epbDropCount :: Word64 }
    -> Option EnhancedPacket

data InboundOutbound =
    Inbound
  | Outbound
  | InboundOutboundNA

instance Enum InboundOutbound where
  toEnum 0b00  = InboundOutboundNA
  toEnum 0b01  = Inbound
  toEnum 0b10  = Outbound
  toEnum other = error
               $ "InboundOutbound specification unrecognized: " <> show other
  fromEnum InboundOutboundNA = 0b00
  fromEnum Inbound           = 0b01
  fromEnum Outbound          = 0b10

data ReceptionType =
    Unspecified
  | Unicast
  | Multicast
  | Broadcast
  | Promiscuous

instance Enum ReceptionType where
  toEnum 0b000 = Unspecified
  toEnum 0b001 = Unicast
  toEnum 0b010 = Multicast
  toEnum 0b011 = Broadcast
  toEnum 0b100 = Promiscuous
  toEnum other = error ("Unknown reception type: " <> show other)
  fromEnum Unspecified = 0b000
  fromEnum Unicast     = 0b001
  fromEnum Multicast   = 0b010
  fromEnum Broadcast   = 0b011
  fromEnum Promiscuous = 0b100


data OptionCode (a :: BlockType) where
    OptEnd :: OptionCode a
    OptComment :: OptionCode a
    OptBlockSpecific :: Word16 -> OptionCode a
    OptCustom :: { customContainsString :: Bool
                 , customDoCopy         :: Bool
                 } -> OptionCode a
    OptSHBHardware  :: OptionCode SectionHeader
    OptSHBOS        :: OptionCode SectionHeader
    OptSHBUserAppl  :: OptionCode SectionHeader
    OptIDBName      :: OptionCode IfDesc
    OptIDBDesc      :: OptionCode IfDesc
    OptIDBIPv4Addr  :: OptionCode IfDesc
    OptIDBIPv6Addr  :: OptionCode IfDesc
    OptIDBEUIAddr   :: OptionCode IfDesc
    OptIDBSpeed     :: OptionCode IfDesc
    OptIDBTSResol   :: OptionCode IfDesc
    OptIDBTZ        :: OptionCode IfDesc
    OptIDBFilter    :: OptionCode IfDesc
    OptIDBOS        :: OptionCode IfDesc
    OptIDBFCSLen    :: OptionCode IfDesc
    OptIDBTSOffset  :: OptionCode IfDesc
    OptIDBHardware  :: OptionCode IfDesc
    OptEPBDropCount :: OptionCode EnhancedPacket
    OptEPBHash      :: OptionCode EnhancedPacket
    OptEPBFlags     :: OptionCode EnhancedPacket

decodeOptionCode :: Proxy a
                 -> Word16
                 -> OptionCode a
decodeOptionCode _     0 = OptEnd
decodeOptionCode _     1 = OptComment
decodeOptionCode _  2988 = OptCustom True  True
decodeOptionCode _  2989 = OptCustom False True
decodeOptionCode _ 19372 = OptCustom True  False
decodeOptionCode _ 19373 = OptCustom False False

decodeBlockSpecific :: forall bt
                     . Endianness
                    -> OptionCode bt
                    -> WS.WordString
                    -> Option     bt
decodeBlockSpecific _ oc ws =
  case oc of
    OptSHBOS        -> decodeTextOption   SHBOS        ws
    OptSHBHardware  -> decodeTextOption   SHBHardware  ws
    OptSHBUserAppl  -> decodeTextOption   SHBOS        ws
    OptEPBFlags     -> decodeWordOption   decodeEPBFlags ws
    OptEPBHash      ->                    EPBHash      ws
    OptEPBDropCount -> decodeWord64Option EPBDropCount ws
    other           -> undefined

decodeEPBFlags      :: Word32 -> Option EnhancedPacket
decodeEPBFlags aWord = EPBFlags {..}
  where
    epbInboundOutbound  = toEnum
                        $ fromIntegral (aWord .&. 0b11)
    epbReceptionType    = toEnum
                        $ fromIntegral ((aWord `shiftR` 3) .&. 0b111)
    epbFCSLength        = fromIntegral
                        $ (aWord `shiftR` 5) .&. 0b1111 -- actually 4 bits
    epbLinkLayerErrors  = fromIntegral
                        $ aWord `shiftR` 16

decodeOptions ::  Endianness
              ->  Proxy  bt
              ->  WS.WordString
              -> [Option bt]
decodeOptions endianness bt ws =
    case optCode of
      OptEnd -> []
      other  -> decodedOption optCode
              : decodeOptions endianness bt rest
  where
    decodedOption OptEnd = error "Impossible!"
    decodedOption OptCustom { customContainsString = True
                  , customDoCopy } =
           CustomString { customCopy=customDoCopy, .. }
    decodedOption OptCustom { customContainsString = False
                  , customDoCopy } =
           CustomBinary { customCopy=customDoCopy, .. }
        -- TODO: decode per-block options
    decodedOption OptComment = Comment
                    $ Text.decodeUtf8
                    $ WS.toBS optionValue
    decodedOption optionCode =
      decodeBlockSpecific endianness
                          optionCode
                          optionValue
        --optionCode  -> Option {..}
    -- TODO: this swapping is suspect
    optCode      = decodeOptionCode Proxy
                 $ fromIntegral
                   (swapper endianness
                           (ws `WS.index` 0)
                .&. 0xFFFF)
    optionLen    = (swapper endianness
                           (ws `WS.index` 0)
                .&. 0xFFFF0000)
                `shiftL`  16
    optionValue  = WS.takeBytes (fromIntegral optionLen)
                 $ WS.drop 1 ws
    customBinary = WS.drop 1 optionValue
    customString = Text.decodeUtf8
                 $ WS.toBS customBinary
    customPEN    = WS.index ws 1
    rest         = WS.drop (fromIntegral $ optionLen + 1)
                            ws

decodeTextOption :: (Text -> Option a)
                 ->  WS.WordString
                 ->          Option a
decodeTextOption opt = opt
                     . Text.decodeUtf8
                     . WS.toBS
decodeWord64Option :: (Word64 -> Option a)
                   ->  WS.WordString
                   ->            Option a
decodeWord64Option opt optionValue =
     assert (WS.length optionValue == 2)
     -- fixme: word swap
  $  opt
  $   fromIntegral (WS.index optionValue 0)
 .|. (fromIntegral (WS.index optionValue 1)
        `shiftR` 32)
   -- ignoring high word for now

decodeWordOption :: (Word32 -> Option a)
                   ->  WS.WordString
                   ->            Option a
decodeWordOption opt  ws =
    assert (WS.length ws == 1)
  $ opt
  $ ws `WS.index` 0

{-# LANGUAGE ForeignFunctionInterface #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.Foreign where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Network.Socket
import Data.Bits

{# pointer *SESSION as Session newtype #}

{# pointer *KNOWNHOSTS as KnownHosts newtype #}

{# pointer *CHANNEL as Channel newtype #}

data KnownHostType =
    TYPE_MASK
  | TYPE_PLAIN
  | TYPE_SHA1
  | TYPE_CUSTOM
  | KEYENC_MASK
  | KEYENC_RAW
  | KEYENC_BASE64
  | KEY_MASK
  | KEY_SHIFT
  | KEY_RSA1
  | KEY_SSHRSA
  | KEY_SSHDSS
  deriving (Eq, Show)

kht2int :: KnownHostType -> CInt
kht2int TYPE_MASK   = 0xffff
kht2int TYPE_PLAIN  = 1
kht2int TYPE_SHA1   = 2
kht2int TYPE_CUSTOM = 3
kht2int KEYENC_MASK = 3 `shiftL` 16
kht2int KEYENC_RAW  = 1 `shiftL` 16
kht2int KEYENC_BASE64 = 2 `shiftL` 16
kht2int KEY_MASK    = 3 `shiftL` 18
kht2int KEY_SHIFT   = 18
kht2int KEY_RSA1    = 1 `shiftL` 18
kht2int KEY_SSHRSA  = 2 `shiftL` 18
kht2int KEY_SSHDSS  = 3 `shiftL` 18

typemask2int :: [KnownHostType] -> CInt
typemask2int list = foldr (.|.) 0 (map kht2int list)

data KnownHostResult =
    MATCH
  | MISMATCH
  | NOTFOUND
  | FAILURE
  deriving (Eq, Show, Ord, Enum)

int2khresult :: CInt -> KnownHostResult
int2khresult = toEnum . fromIntegral

data KnownHost = KnownHost {
  khMagic :: CUInt,
  khNode :: Ptr (),
  khName :: String,
  khKey :: String,
  khTypeMask :: [KnownHostType] }
  deriving (Eq, Show)

data Direction = INBOUND | OUTBOUND
  deriving (Eq, Show)

int2dir 1 = [INBOUND]
int2dir 2 = [OUTBOUND]
int2dir 3 = [INBOUND, OUTBOUND]
int2dir x = error $ "Unknown direction: " ++ show x

init_crypto :: Bool -> CInt
init_crypto False = 1
init_crypto True  = 0

ssh2socket :: Socket -> CInt
ssh2socket (MkSocket s _ _ _ _) = s

type CStringCLen = (CString, CUInt)

withCStringLenIntConv :: String -> (CStringCLen -> IO a) -> IO a
withCStringLenIntConv str fn =
  withCStringLen str (\(ptr, len) -> fn (ptr, fromIntegral len))

{# fun init as initialize
  { init_crypto `Bool' } -> `Int' #}

{# fun exit as exit { } -> `()' #}

initSession :: IO Session
initSession = do
  ptr <- {# call session_init_ex #} nullFunPtr nullFunPtr nullFunPtr nullPtr
  return ptr

{# fun session_free as freeSession
  { id `Session' } -> `Int' #}

{# fun session_handshake as handshake
  { id `Session', ssh2socket `Socket' } -> `Int' #}

{# fun knownhost_init as initKnownHosts
  { id `Session' } -> `KnownHosts' id #}

{# fun knownhost_free as freeKnownHosts
  { id `KnownHosts' } -> `()' #}

{# fun knownhost_readfile as knownHostsReadFile_
  { id `KnownHosts', `String', id `CInt' } -> `Int' #}

knownHostsReadFile :: KnownHosts -> String -> IO Int
knownHostsReadFile kh path = knownHostsReadFile_ kh path 1

{# fun session_hostkey as getHostKey
  { id `Session', alloca- `CULong' peek*, alloca- `CInt' peek* } -> `String' #}

{# fun knownhost_checkp as checkKnownHost_
  { id `KnownHosts',
    `String',
    `Int',
    `String',
    `Int',
    typemask2int `[KnownHostType]',
    castPtr `Ptr ()' } -> `KnownHostResult' int2khresult #}

checkKnownHost :: KnownHosts -> String -> Int -> String -> [KnownHostType] -> IO KnownHostResult
checkKnownHost kh host port key mask = checkKnownHost_ kh host port key (length key) mask nullPtr

{# fun userauth_publickey_fromfile_ex as publicKeyAuthFile
  { id `Session', `String' &, `String', `String', `String' } -> `Int' #}

{# fun channel_open_ex as openSessionChannelEx
  { id `Session',
   `String' &,
   `Int', `Int',
   `String' & } -> `Channel' id #}

openChannelSession :: Session -> IO Channel
openChannelSession s = openSessionChannelEx s "session" 65536 32768 ""

{# fun channel_process_startup as channelProcess
  { id `Channel',
    `String' &,
    `String' & } -> `Int' #}

channelExecute :: Channel -> String -> IO Int
channelExecute c command = channelProcess c "exec" command

channelShell :: Channel -> String -> IO Int
channelShell c command = channelProcess c "shell" command

{# fun channel_read_ex as readChannelEx
  { id `Channel',
    `Int',
    alloca- `String' peekCString*,
    `Int' } -> `Int' #}

readChannel :: Channel -> Int -> IO (Int, String)
readChannel c sz = readChannelEx c 0 sz

{# fun channel_close as closeChannel
  { id `Channel' } -> `Int' #}

{# fun session_block_direction as blockedDirections
  { id `Session' } -> `[Direction]' int2dir #}

peekCStringPtr :: Ptr CString -> IO String
peekCStringPtr ptr = peek ptr >>= peekCString

{# fun session_last_error as getLastError_
  { id `Session',
    alloca- `String' peekCStringPtr*,
    castPtr `Ptr Int',
    `Int' } -> `Int' #}

getLastError :: Session -> IO (Int, String)
getLastError s = getLastError_ s nullPtr 0

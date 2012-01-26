{-# LANGUAGE ForeignFunctionInterface #-}

#include "libssh2_local.h"
#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Foreign where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Network.Socket
import Data.Bits
import Data.Int
import Data.Time.Clock.POSIX

import Network.SSH.Client.LibSSH2.Types
import Network.SSH.Client.LibSSH2.Errors

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

{# fun init as initialize
  { init_crypto `Bool' } -> `Int' handleInt* #}

{# fun exit as exit { } -> `()' #}

initSession :: IO Session
initSession = do
  ptr <- {# call session_init_ex #} nullFunPtr nullFunPtr nullFunPtr nullPtr
  handleNullPtr ptr

{# fun session_free as freeSession
  { toPointer `Session' } -> `Int' handleInt* #}

{# fun session_disconnect_ex as disconnectSessionEx
  { toPointer `Session', `Int', `String', `String' } -> `Int' handleInt* #}

disconnectSession :: Session -> String -> IO Int
disconnectSession s msg = disconnectSessionEx s 11 msg ""

{# fun session_handshake as handshake
  { toPointer `Session', ssh2socket `Socket' } -> `Int' handleInt* #}

{# fun knownhost_init as initKnownHosts
  { toPointer `Session' } -> `KnownHosts' handleNullPtr* #}

{# fun knownhost_free as freeKnownHosts
  { toPointer `KnownHosts' } -> `()' #}

{# fun knownhost_readfile as knownHostsReadFile_
  { toPointer `KnownHosts', `String', id `CInt' } -> `Int' handleInt* #}

knownHostsReadFile :: KnownHosts -> String -> IO Int
knownHostsReadFile kh path = knownHostsReadFile_ kh path 1

{# fun session_hostkey as getHostKey
  { toPointer `Session', alloca- `CUInt' peek*, alloca- `CInt' peek* } -> `String' #}

{# fun knownhost_checkp as checkKnownHost_
  { toPointer `KnownHosts',
    `String',
    `Int',
    `String',
    `Int',
    typemask2int `[KnownHostType]',
    castPtr `Ptr ()' } -> `KnownHostResult' int2khresult #}

checkKnownHost :: KnownHosts -> String -> Int -> String -> [KnownHostType] -> IO KnownHostResult
checkKnownHost kh host port key mask = checkKnownHost_ kh host port key (length key) mask nullPtr

{# fun userauth_publickey_fromfile_ex as publicKeyAuthFile
  { toPointer `Session',
    `String' &,
    `String',
    `String',
    `String' } -> `Int' handleInt* #}

{# fun channel_open_ex as openSessionChannelEx
  { toPointer `Session',
   `String' &,
   `Int', `Int',
   `String' & } -> `Channel' handleNullPtr* #}

openChannelSession :: Session -> IO Channel
openChannelSession s = openSessionChannelEx s "session" 65536 32768 ""

{# fun channel_process_startup as channelProcess
  { toPointer `Channel',
    `String' &,
    `String' & } -> `Int' handleInt* #}

channelExecute :: Channel -> String -> IO Int
channelExecute c command = channelProcess c "exec" command

channelShell :: Channel -> String -> IO Int
channelShell c command = channelProcess c "shell" command

{# fun channel_read_ex as readChannelEx
  { toPointer `Channel',
    `Int',
    alloca- `String' peekCString*,
    `Int' } -> `Int' handleInt* #}

readChannel :: Channel -> Int -> IO (Int, String)
readChannel c sz = readChannelEx c 0 sz

{# fun channel_write_ex as writeChannelEx
  { toPointer `Channel',
    `Int',
    `String' & } -> `Int' handleInt* #}

writeChannel :: Channel -> String -> IO Int
writeChannel ch str = writeChannelEx ch 0 str

{# fun channel_close as closeChannel
  { toPointer `Channel' } -> `Int' handleInt* #}

{# fun channel_free as freeChannel
  { toPointer `Channel' } -> `Int' handleInt* #}

{# fun session_block_directions as blockedDirections
  { toPointer `Session' } -> `[Direction]' int2dir #}

{# fun channel_get_exit_status as channelExitStatus
  { toPointer `Channel' } -> `Int' handleInt* #}

{# fun channel_get_exit_signal as channelExitSignal_
  { toPointer `Channel',
    alloca- `String' peekCStringPtr*,
    castPtr `Ptr Int',
    alloca- `Maybe String' peekMaybeCStringPtr*,
    castPtr `Ptr Int',
    alloca- `Maybe String' peekMaybeCStringPtr*,
    castPtr `Ptr Int' } -> `Int' handleInt* #}

channelExitSignal :: Channel -> IO (Int, String, Maybe String, Maybe String)
channelExitSignal ch = channelExitSignal_ ch nullPtr nullPtr nullPtr

{# fun scp_send64 as scpSendChannel
  { toPointer `Session',
    `String',
    `Int',
    `Int64',
    round `POSIXTime',
    round `POSIXTime' } -> `Channel' handleNullPtr* #}

-- TODO: receive struct stat also.
scpReceiveChannel :: Session -> String -> IO Channel
scpReceiveChannel s path = do
  ptr <- withCString path $ \pathptr ->
            allocaBytes {# sizeof stat_t #} $ \statptr ->
              {# call scp_recv #} (toPointer s) pathptr statptr
  handleNullPtr ptr


{-# LANGUAGE CPP, ForeignFunctionInterface #-}

#include "libssh2_local.h"
#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Foreign
  (-- * Types
   KnownHosts, KnownHostResult (..), KnownHostType (..), KnownHost (..),

   -- * Session functions
   initialize, exit,
   initSession, freeSession, disconnectSession,
   handshake,
   setBlocking,
   
   -- * Known hosts functions
   initKnownHosts, freeKnownHosts, knownHostsReadFile,
   getHostKey, checkKnownHost,

   -- * Authentication
   publicKeyAuthFile,

   -- * Channel functions
   openChannelSession, closeChannel, freeChannel,
   channelSendEOF, channelWaitEOF, channelIsEOF,
   readChannel, writeChannel,
   writeChannelFromHandle, readChannelToHandle,
   channelProcess, channelExecute, channelShell,
   requestPTY, requestPTYEx,
   channelExitStatus, channelExitSignal,
   scpSendChannel, scpReceiveChannel,

   -- * Debug
   TraceFlag (..), setTraceMode
  ) where

import Foreign
import Foreign.C.Types
import Foreign.C.String
import System.IO
import Network.Socket (Socket(MkSocket))
import Data.Time.Clock.POSIX
import qualified Data.ByteString as BSS
import qualified Data.ByteString.Unsafe as BSS

import Network.SSH.Client.LibSSH2.Types
import Network.SSH.Client.LibSSH2.Errors

-- Known host flags. See libssh2 documentation.
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

-- Result of matching host against known_hosts.
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

init_crypto :: Bool -> CInt
init_crypto False = 1
init_crypto True  = 0

ssh2socket :: Socket 
#ifdef mingw32_HOST_OS
           -> CUInt
#else
           -> CInt
#endif
ssh2socket (MkSocket s _ _ _ _) =
#ifdef mingw32_HOST_OS
  (fromIntegral s)
#else
  s
#endif

{# fun init as initialize_
  { init_crypto `Bool' } -> `Int' #}

-- | Initialize libssh2. Pass True to enable encryption
-- or False to disable it.
initialize :: Bool -> IO ()
initialize flags = void . handleInt Nothing $ initialize_ flags

-- | Deinitialize libssh2.
#ifdef mingw32_HOST_OS
foreign import ccall safe "libssh2_exit"
  exit:: IO ()
#else
{# fun exit as exit { } -> `()' #}
#endif

-- | Create Session object
initSession :: IO Session
initSession = handleNullPtr Nothing sessionFromPointer $ 
  {# call session_init_ex #} nullFunPtr nullFunPtr nullFunPtr nullPtr

{# fun session_free as freeSession_
  { toPointer `Session' } -> `Int' #}

-- | Free Session object's memory
freeSession :: Session -> IO ()
freeSession session = void . handleInt (Just session) $ freeSession_ session

{# fun session_disconnect_ex as disconnectSessionEx
  { toPointer `Session', `Int', `String', `String' } -> `Int' #}

-- | Disconnect session (but do not free memory)
disconnectSession :: Session
                  -> String  -- ^ Goodbye message
                  -> IO () 
disconnectSession s msg = void . handleInt (Just s) $ disconnectSessionEx s 11 msg ""

{# fun session_set_blocking as setBlocking
  { toPointer `Session', bool2int `Bool' } -> `()' #}

bool2int :: Bool -> CInt
bool2int True  = 1
bool2int False = 0

{# fun session_handshake as handshake_
  { toPointer `Session', ssh2socket `Socket' } -> `Int' #}

-- | Run SSH handshake on network socket.
handshake :: Session -> Socket -> IO ()
handshake session socket = do
  sessionSetSocket session (Just socket)
  void . handleInt (Just session) $ handshake_ session socket

{# fun knownhost_init as initKnownHosts_
  { toPointer `Session' } -> `Ptr ()' id #}

-- | Create KnownHosts object for given session.
initKnownHosts :: Session -> IO KnownHosts
initKnownHosts session = handleNullPtr Nothing knownHostsFromPointer $ initKnownHosts_ session

-- | Free KnownHosts object's memory
{# fun knownhost_free as freeKnownHosts
  { toPointer `KnownHosts' } -> `()' #}

{# fun knownhost_readfile as knownHostsReadFile_
  { toPointer `KnownHosts', `String', id `CInt' } -> `Int' #}

-- | Read known hosts from file
knownHostsReadFile :: KnownHosts
                   -> FilePath   -- ^ Path to known_hosts file
                   -> IO Int
knownHostsReadFile kh path = handleInt Nothing $ knownHostsReadFile_ kh path 1

-- | Get remote host public key
{# fun session_hostkey as getHostKey
  { toPointer `Session', alloca- `Size' peek*, alloca- `CInt' peek* } -> `String' #}

{# fun knownhost_checkp as checkKnownHost_
  { toPointer `KnownHosts',
    `String',
    `Int',
    `String',
    `Int',
    typemask2int `[KnownHostType]',
    castPtr `Ptr ()' } -> `KnownHostResult' int2khresult #}

-- | Check host data against known hosts.
checkKnownHost :: KnownHosts         -- 
               -> String             -- ^ Host name
               -> Int                -- ^ Port number (usually 22)
               -> String             -- ^ Host public key
               -> [KnownHostType]    -- ^ Host flags (see libssh2 documentation)
               -> IO KnownHostResult
checkKnownHost kh host port key flags = checkKnownHost_ kh host port key (length key) flags nullPtr

-- TODO: I don't see the '&' in the libssh2 docs?
{# fun userauth_publickey_fromfile_ex as publicKeyAuthFile_
  { toPointer `Session',
    `String' &,
    `String',
    `String',
    `String' } -> `Int' #}

-- | Perform public key authentication.
publicKeyAuthFile :: Session -- ^ Session
                  -> String  -- ^ Username
                  -> String  -- ^ Path to public key
                  -> String  -- ^ Path to private key
                  -> String  -- ^ Passphrase
                  -> IO ()
publicKeyAuthFile session username public private passphrase = void . handleInt (Just session) $ 
  publicKeyAuthFile_ session username public private passphrase

{# fun channel_open_ex as openSessionChannelEx
  { toPointer `Session',
   `String' &,
   `Int', `Int',
   `String' & } -> `Ptr ()' id #}

-- | Open a channel for session.
openChannelSession :: Session -> IO Channel
openChannelSession s = handleNullPtr (Just s) (channelFromPointer s) $ 
  openSessionChannelEx s "session" 65536 32768 ""

channelProcess :: Channel -> String -> String -> IO () 
channelProcess ch kind command = void . handleInt (Just $ channelSession ch) $
  channelProcessStartup_ ch kind command

-- | Execute command
channelExecute :: Channel -> String -> IO () 
channelExecute c command = channelProcess c "exec" command

{# fun channel_process_startup as channelProcessStartup_ 
  { toPointer `Channel',
    `String' &,
    `String' & } -> `Int' #}

-- | Execute shell command
channelShell :: Channel -> IO () 
channelShell c = void . handleInt (Just $ channelSession c) $ channelProcessStartup_ c "shell" ""  

{# fun channel_request_pty_ex as requestPTYEx
  { toPointer `Channel',
    `String' &,
    `String' &,
    `Int', `Int',
    `Int', `Int' } -> `Int' #}

requestPTY :: Channel -> String -> IO () 
requestPTY ch term = void . handleInt (Just $ channelSession ch) $ requestPTYEx ch term "" 0 0 0 0

readChannelEx :: Channel -> Int -> Size -> IO BSS.ByteString 
readChannelEx ch i size =
  allocaBytes (fromIntegral size) $ \buffer -> do
    rc <- handleInt (Just $ channelSession ch) $ {# call channel_read_ex #} (toPointer ch) (fromIntegral i) buffer size
    BSS.packCStringLen (buffer, fromIntegral rc)

-- | Read data from channel.
readChannel :: Channel         -- 
            -> Size             -- ^ Amount of data to read
            -> IO BSS.ByteString 
readChannel c sz = readChannelEx c 0 sz

-- | Write data to channel.
writeChannel :: Channel -> BSS.ByteString -> IO () 
writeChannel ch bs = 
    BSS.unsafeUseAsCString bs $ go 0 (fromIntegral $ BSS.length bs)
  where
    go :: Int -> CULong -> CString -> IO () 
    go offset len cstr = do
      written <- handleInt (Just $ channelSession ch) 
                           $ {# call channel_write_ex #} (toPointer ch) 
                                                         0 
                                                         (cstr `plusPtr` offset) 
                                                         (fromIntegral len)
      if fromIntegral written < len 
        then go (offset + fromIntegral written) (len - fromIntegral written) cstr
        else return ()

{# fun channel_send_eof as channelSendEOF_
  { toPointer `Channel' } -> `Int' #}

channelSendEOF :: Channel -> IO ()
channelSendEOF channel = void . handleInt (Just $ channelSession channel) $ channelSendEOF_ channel

{# fun channel_wait_eof as channelWaitEOF_
  { toPointer `Channel' } -> `Int' #}

channelWaitEOF :: Channel -> IO ()
channelWaitEOF channel = void . handleInt (Just $ channelSession channel) $ channelWaitEOF_ channel

data TraceFlag =
    T_TRANS
  | T_KEX
  | T_AUTH
  | T_CONN
  | T_SCP
  | T_SFTP
  | T_ERROR
  | T_PUBLICKEY
  | T_SOCKET
  deriving (Eq, Show)

tf2int :: TraceFlag -> CInt
tf2int T_TRANS = 1 `shiftL` 1
tf2int T_KEX   = 1 `shiftL` 2
tf2int T_AUTH  = 1 `shiftL` 3
tf2int T_CONN  = 1 `shiftL` 4
tf2int T_SCP   = 1 `shiftL` 5
tf2int T_SFTP  = 1 `shiftL` 6
tf2int T_ERROR = 1 `shiftL` 7
tf2int T_PUBLICKEY = 1 `shiftL` 8
tf2int T_SOCKET = 1 `shiftL` 9

trace2int :: [TraceFlag] -> CInt
trace2int flags = foldr (.|.) 0 (map tf2int flags)

{# fun trace as setTraceMode
  { toPointer `Session', trace2int `[TraceFlag]' } -> `()' #}

-- | Write all data to channel from handle.
-- Returns amount of transferred data.
writeChannelFromHandle :: Channel -> Handle -> IO Integer
writeChannelFromHandle ch h = 
  let
    go :: Integer -> Ptr a -> IO Integer
    go done buffer = do
      sz <- hGetBuf h buffer bufferSize
      send 0 (fromIntegral sz) buffer
      let newDone = done + fromIntegral sz 
      if sz < bufferSize
        then return newDone 
        else go newDone buffer
 
    send :: Int -> CLong -> Ptr a -> IO () 
    send _ 0 _ = return () 
    send written size buffer = do
      sent <- handleInt (Just $ channelSession ch) $ 
                {# call channel_write_ex #}
                  (toPointer ch)
                  0
                  (plusPtr buffer written)
                  (fromIntegral size)
      send (written + fromIntegral sent) (size - fromIntegral sent) buffer

    bufferSize = 0x100000

  in allocaBytes bufferSize $ go 0 

-- | Read all data from channel to handle.
-- Returns amount of transferred data.
readChannelToHandle :: Channel -> Handle -> Offset -> IO Integer
readChannelToHandle ch h fileSize = do
    allocaBytes bufferSize $ \buffer ->
        readChannelCB ch buffer bufferSize fileSize callback
  where
    callback buffer size = hPutBuf h buffer size

    bufferSize :: Int
    bufferSize = 0x100000

readChannelCB :: Channel -> CString -> Int -> Offset -> (CString -> Int -> IO ()) -> IO Integer
readChannelCB ch buffer bufferSize fileSize callback =
  let go got = do
        let toRead = min (fromIntegral fileSize - got) (fromIntegral bufferSize)
        sz <- handleInt (Just $ channelSession ch) $ 
                {# call channel_read_ex #}
                  (toPointer ch)
                  0
                  buffer
                  (fromIntegral toRead)
        let isz :: Integer
            isz = fromIntegral sz
        callback buffer (fromIntegral sz)
        eof <- {# call channel_eof #} (toPointer ch)
        let newGot = got + fromIntegral sz
        if  (eof == 1) || (newGot == fromIntegral fileSize)
          then do
               return isz
          else do
               rest <- go newGot
               return $ isz + rest
  in go (0 :: Integer)

{# fun channel_eof as channelIsEOF
  { toPointer `Channel' } -> `Bool' handleBool* #}

{# fun channel_close as closeChannel_
  { toPointer `Channel' } -> `Int' #}

-- | Close channel (but do not free memory)
closeChannel :: Channel -> IO ()
closeChannel channel = void . handleInt (Just $ channelSession channel) $ closeChannel_ channel

{# fun channel_free as freeChannel_
  { toPointer `Channel' } -> `Int' #}

-- | Free channel object's memory
freeChannel :: Channel -> IO ()
freeChannel channel = void . handleInt (Just $ channelSession channel) $ freeChannel_ channel

-- | Get channel exit status
{# fun channel_get_exit_status as channelExitStatus
  { toPointer `Channel' } -> `Int' #}

{# fun channel_get_exit_signal as channelExitSignal_
  { toPointer `Channel',
    alloca- `String' peekCStringPtr*,
    castPtr `Ptr Int',
    alloca- `Maybe String' peekMaybeCStringPtr*,
    castPtr `Ptr Int',
    alloca- `Maybe String' peekMaybeCStringPtr*,
    castPtr `Ptr Int' } -> `Int' #}

-- | Get channel exit signal. Returns:
-- (possibly error code, exit signal name, possibly error message, possibly language code).
channelExitSignal :: Channel -> IO (Int, String, Maybe String, Maybe String)
channelExitSignal ch = handleInt (Just $ channelSession ch) $ channelExitSignal_ ch nullPtr nullPtr nullPtr

{# fun scp_send64 as scpSendChannel_
  { toPointer `Session',
    `String',
    `Int',
    `Int64',
    round `POSIXTime',
    round `POSIXTime' } -> `Ptr ()' id #}

-- | Create SCP file send channel.
scpSendChannel :: Session -> String -> Int -> Int64 -> POSIXTime -> POSIXTime -> IO Channel
scpSendChannel session remotePath mode size mtime atime = handleNullPtr (Just session) (channelFromPointer session) $ 
  scpSendChannel_ session remotePath mode size mtime atime

type Offset = {# type off_t #}

-- {# pointer *stat_t as Stat newtype #}

-- | Create SCP file receive channel.
-- TODO: receive struct stat also.
scpReceiveChannel :: Session -> FilePath -> IO (Channel, Offset)
scpReceiveChannel s path = do
  withCString path $ \pathptr ->
     allocaBytes {# sizeof stat_t #} $ \statptr -> do
       channel <- handleNullPtr (Just s) (channelFromPointer s) $ {# call scp_recv #} (toPointer s) pathptr statptr
       size <- {# get stat_t->st_size #} statptr
       return (channel, size)

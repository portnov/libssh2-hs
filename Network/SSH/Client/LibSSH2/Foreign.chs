{-# LANGUAGE ForeignFunctionInterface #-}

#include "libssh2_local.h"
#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Foreign
  (-- * Types
   KnownHosts, KnownHostResult (..), KnownHostType (..),
   Direction (..),

   -- * Session functions
   initialize, exit,
   initSession, freeSession, disconnectSession,
   handshake,
   blockedDirections,
   
   -- * Known hosts functions
   initKnownHosts, freeKnownHosts, knownHostsReadFile,
   getHostKey, checkKnownHost,

   -- * Authentication
   publicKeyAuthFile,

   -- * Channel functions
   openChannelSession, closeChannel, freeChannel,
   readChannel, writeChannel,
   writeChannelFromHandle, readChannelToHandle,
   channelProcess, channelExecute, channelShell,
   channelExitStatus, channelExitSignal,
   scpSendChannel, scpReceiveChannel
  ) where

import Control.Exception
import Control.Monad
import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import System.IO
import Network.Socket
import Data.Bits
import Data.Int
import Data.Time.Clock.POSIX
import Text.Printf

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

-- | Session directions
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

-- | Initialize libssh2. Pass True to enable encryption
-- or False to disable it.
{# fun init as initialize
  { init_crypto `Bool' } -> `Int' handleInt* #}

-- | Deinitialize libssh2.
{# fun exit as exit { } -> `()' #}

-- | Create Session object
initSession :: IO Session
initSession = do
  ptr <- {# call session_init_ex #} nullFunPtr nullFunPtr nullFunPtr nullPtr
  handleNullPtr ptr

-- | Free Session object's memory
{# fun session_free as freeSession
  { toPointer `Session' } -> `Int' handleInt* #}

{# fun session_disconnect_ex as disconnectSessionEx
  { toPointer `Session', `Int', `String', `String' } -> `Int' handleInt* #}

-- | Disconnect session (but do not free memory)
disconnectSession :: Session
                  -> String  -- ^ Goodbye message
                  -> IO Int
disconnectSession s msg = disconnectSessionEx s 11 msg ""

-- | Run SSH handshake on network socket.
{# fun session_handshake as handshake
  { toPointer `Session', ssh2socket `Socket' } -> `Int' handleInt* #}

-- | Create KnownHosts object for given session.
{# fun knownhost_init as initKnownHosts
  { toPointer `Session' } -> `KnownHosts' handleNullPtr* #}

-- | Free KnownHosts object's memory
{# fun knownhost_free as freeKnownHosts
  { toPointer `KnownHosts' } -> `()' #}

{# fun knownhost_readfile as knownHostsReadFile_
  { toPointer `KnownHosts', `String', id `CInt' } -> `Int' handleInt* #}

-- | Read known hosts from file
knownHostsReadFile :: KnownHosts
                   -> FilePath   -- ^ Path to known_hosts file
                   -> IO Int
knownHostsReadFile kh path = knownHostsReadFile_ kh path 1

-- | Get remote host public key
{# fun session_hostkey as getHostKey
  { toPointer `Session', alloca- `CULong' peek*, alloca- `CInt' peek* } -> `String' #}

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
checkKnownHost kh host port key mask = checkKnownHost_ kh host port key (length key) mask nullPtr

-- | Perform public key authentication.
-- Arguments are: session, username, path to public key file,
-- path to private key file, passphrase.
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

-- | Open a channel for session.
openChannelSession :: Session -> IO Channel
openChannelSession s = openSessionChannelEx s "session" 65536 32768 ""

-- | Run a process within channel. Arguments are:
-- type of process and request.
{# fun channel_process_startup as channelProcess
  { toPointer `Channel',
    `String' &,
    `String' & } -> `Int' handleInt* #}

-- | Execute command
channelExecute :: Channel -> String -> IO Int
channelExecute c command = channelProcess c "exec" command

-- | Execute shell command
channelShell :: Channel -> String -> IO Int
channelShell c command = channelProcess c "shell" command

type Size = {# type size_t #}

{# fun channel_read_ex as readChannelEx
  { toPointer `Channel',
    `Int',
    alloca- `String' peekCAString*,
    id `Size' } -> `Int' handleInt* #}

-- | Read data from channel.
-- Returns amount of given data and data itself.
-- NOTE: returns bytes sequence, i.e. not Unicode.
readChannel :: Channel         -- 
            -> Size             -- ^ Amount of data to read
            -> IO (Int, String)
readChannel c sz = readChannelEx c 0 sz

{# fun channel_write_ex as writeChannelEx
  { toPointer `Channel',
    `Int',
    withCStringLenIntConv* `String' & } -> `Int' handleInt* #}

-- | Write data to channel.
-- Returns amount of written data.
writeChannel :: Channel -> String -> IO Int
writeChannel ch str = writeChannelEx ch 0 str

{# fun channel_send_eof as channelSendEOF
  { toPointer `Channel' } -> `Int' handleInt* #}

-- | Write all data to channel from handle.
-- Returns amount of transferred data.
--writeChannelFromHandle :: Channel -> Handle -> IO Integer
writeChannelFromHandle session ch handle = 
  let
    go h done fileSize buffer = do
      sz <- hGetBuf h buffer bufferSize
      putStrLn $ printf ">> Done: %s / %s" (show done) (show fileSize)
      putStrLn $ "read: " ++ show sz
      putStrLn $ printf "Calling send 0 %s %s" (show sz) (show buffer)
      sent <- send 0 (fromIntegral sz) buffer
      let newDone = done + sent
      if sz < bufferSize
        then do
             --channelSendEOF ch
             return $ fromIntegral sz
        else do
             rest <- go h newDone  fileSize buffer
             return $ fromIntegral sz + rest
    
    send written 0 _ = return written
    send written size buffer = do
      putStrLn $ printf "channel_write_ex ch 0 %s %s" (show $ plusPtr buffer written) (show size)
      sent <- {# call channel_write_ex #}
                  (toPointer ch)
                  0
                  (plusPtr buffer written)
                  (fromIntegral size)
      putStrLn $ printf "sent: %s, remained: %s" (show sent) (show $ size - sent)
      when (sent < 0) $ do
          throw (int2error sent)
      putStrLn $ printf "send again: %s %s %s" (show $ written + fromIntegral sent) (show $ size - sent) (show buffer)
      send (written + fromIntegral sent) (size - sent) buffer

    bufferSize = 0x100000

  in do
    fileSize <- hFileSize handle
    {# call trace #} (toPointer session) (512)
    allocaBytes bufferSize $ \buffer ->
        go handle 0 fileSize buffer

-- | Read all data from channel to handle.
-- Returns amount of transferred data.
readChannelToHandle :: Channel -> Handle -> Offset -> IO Integer
readChannelToHandle ch handle fileSize = do
    allocaBytes bufferSize $ \buffer ->
        go handle 0 fileSize buffer
  where
    go :: Handle -> Integer -> Offset -> CString -> IO Integer
    go h got fileSize buffer = do
      let toRead = min (fromIntegral fileSize - got) (fromIntegral bufferSize)
      sz <- {# call channel_read_ex #}
                (toPointer ch)
                0
                buffer
                (fromIntegral toRead)
      when (sz < 0) $
          throw (int2error sz)
      let isz :: Integer
          isz = fromIntegral sz
      hPutBuf h buffer (fromIntegral sz)
      eof <- {# call channel_eof #} (toPointer ch)
      let newGot = got + fromIntegral sz
      if  (eof == 1) || (newGot == fromIntegral fileSize)
        then do
             hFlush h
             return isz
        else do
             rest <- go h newGot fileSize buffer
             return $ isz + rest

    bufferSize :: Int
    bufferSize = 0x100000

{# fun channel_eof as channelIsEOF
  { toPointer `Channel' } -> `Bool' handleBool* #}

-- | Close channel (but do not free memory)
{# fun channel_close as closeChannel
  { toPointer `Channel' } -> `Int' handleInt* #}

-- | Free channel object's memory
{# fun channel_free as freeChannel
  { toPointer `Channel' } -> `Int' handleInt* #}

-- | Get currently blocked directions
{# fun session_block_directions as blockedDirections
  { toPointer `Session' } -> `[Direction]' int2dir #}

-- | Get channel exit status
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

-- | Get channel exit signal. Returns:
-- (possibly error code, exit signal name, possibly error message, possibly language code).
channelExitSignal :: Channel -> IO (Int, String, Maybe String, Maybe String)
channelExitSignal ch = channelExitSignal_ ch nullPtr nullPtr nullPtr

-- | Create SCP file send channel.
{# fun scp_send64 as scpSendChannel
  { toPointer `Session',
    `String',
    `Int',
    `Int64',
    round `POSIXTime',
    round `POSIXTime' } -> `Channel' handleNullPtr* #}

type Offset = {# type off_t #}

{# pointer *stat_t as Stat newtype #}

-- | Create SCP file receive channel.
-- TODO: receive struct stat also.
scpReceiveChannel :: Session -> FilePath -> IO (Channel, Offset)
scpReceiveChannel s path = do
  (ptr, sz) <- withCString path $ \pathptr ->
                  allocaBytes {# sizeof stat_t #} $ \statptr -> do
                    p <- {# call scp_recv #} (toPointer s) pathptr statptr
                    size <- {# get stat_t->st_size #} statptr
                    return (p, size)
  channel <- handleNullPtr ptr
  return (channel, sz)



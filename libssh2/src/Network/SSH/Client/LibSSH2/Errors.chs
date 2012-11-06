{-# LANGUAGE ForeignFunctionInterface, DeriveDataTypeable, FlexibleInstances #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Errors
  (-- * Types
   ErrorCode (..),
   NULL_POINTER,

   -- * Utilities
   IntResult (..),

   -- * Functions
   getLastError,
   handleInt,
   handleBool,
   handleNullPtr,
   int2error, error2int,
   blockedDirections,
   threadWaitSession
  ) where

import Control.Exception
import Data.Generics
import Foreign
import Foreign.C.Types
import Control.Monad (when)

import Network.SSH.Client.LibSSH2.Types
import Network.SSH.Client.LibSSH2.WaitSocket

-- | Error codes returned by libssh2.
data ErrorCode =
    NONE
  | SOCKET_NONE
  | BANNER_RECV
  | BANNER_SEND
  | INVALID_MAC
  | KEX_FALIURE
  | ALLOC
  | SOCKET_SEND
  | KEY_EXCHANGE_FAILURE
  | TIMEOUT
  | HOSTKEY_INIT
  | HOSTKEY_SIGN
  | DECRYPT
  | SOCKET_DISCONNECT
  | PROTO
  | PASSWORD_EXPIRED
  | FILE
  | METHOD_NONE
  | AUTHENTICATION_FAILED
  | PUBLICKEY_UNVERIFIED
  | CHANNEL_OUTOFORDER
  | CHANNEL_FAILURE
  | CHANNEL_REQUEST_DENIED
  | CHANNEL_UNKNOWN
  | CHANNEL_WINDOW_EXCEEDED
  | CHANNEL_PACKET_EXCEEDED
  | CHANNEL_CLOSED
  | CHANNEL_EOF_SENT
  | SCP_PROTOCOL
  | ZLIB
  | SOCKET_TIMEOUT
  | SFTP_PROTOCOL
  | REQUEST_DENIED
  | METHOD_NOT_SUPPORTED
  | INVAL
  | INVALID_POLL_TYPE
  | PUBLICKEY_PROTOCOL
  | EAGAIN
  | BUFFER_TOO_SMALL
  | BAD_USE
  | COMPRESS
  | OUT_OF_BOUNDARY
  | AGENT_PROTOCOL
  | SOCKET_RECV
  | ENCRYPT
  | BAD_SOCKET
  deriving (Eq, Show, Ord, Enum, Data, Typeable)

instance Exception ErrorCode

error2int :: (Num i) => ErrorCode -> i
error2int = fromIntegral . negate . fromEnum

int2error :: (Integral i) => i -> ErrorCode
int2error = toEnum . negate . fromIntegral

-- | Exception to throw when null pointer received
-- from libssh2.
data NULL_POINTER = NULL_POINTER
  deriving (Eq, Show, Data, Typeable)

instance Exception NULL_POINTER

class IntResult a where
  intResult :: a -> Int

instance IntResult Int where
  intResult = id

instance IntResult (Int, a) where
  intResult = fst

instance IntResult (Int, a, b) where
  intResult = \(i, _, _) -> i

instance IntResult (Int, a, b, c) where
  intResult = \(i, _, _, _) -> i

instance IntResult CInt where
  intResult = fromIntegral

instance IntResult CLong where
  intResult = fromIntegral

{# fun session_last_error as getLastError_
  { toPointer `Session',
    alloca- `String' peekCStringPtr*,
    castPtr `Ptr Int',
    `Int' } -> `Int' #}

-- | Get last error information.
getLastError :: Session -> IO (Int, String)
getLastError s = getLastError_ s nullPtr 0

-- | Throw an exception if negative value passed,
-- or return unchanged value.
handleInt :: (IntResult a) => Maybe Session -> IO a -> IO a
handleInt s io = do
  x <- io
  let r = intResult x
  if r < 0
    then case int2error r of
           EAGAIN -> threadWaitSession s >> handleInt s io
           err    -> throwIO err
    else return x 

handleBool :: CInt -> IO Bool
handleBool x
  | x == 0 = return False
  | x > 0  = return True
  | otherwise = throw (int2error x)

-- | Throw an exception if null pointer passed,
-- or return it casted to right type.
handleNullPtr :: Maybe Session -> (Ptr () -> IO a) -> IO (Ptr ()) -> IO a
handleNullPtr s fromPointer io = do
  p <- io
  if p == nullPtr 
    then case s of
      Nothing -> throw NULL_POINTER
      Just session -> do
        (r, _) <- getLastError session
        case int2error r of
          EAGAIN -> threadWaitSession (Just session) >> handleNullPtr s fromPointer io
          _      -> throw NULL_POINTER -- TODO: should we throw the error instead?
    else fromPointer p

-- | Get currently blocked directions
{# fun session_block_directions as blockedDirections
  { toPointer `Session' } -> `[Direction]' int2dir #}

threadWaitSession :: Maybe Session -> IO ()
threadWaitSession Nothing = error "EAGAIN thrown without session present"
threadWaitSession (Just s) = do
  mSocket <- sessionGetSocket s
  case mSocket of
    Nothing -> error "EAGAIN thrown on session without socket"
    Just socket -> do 
      dirs <- blockedDirections s
      when (INBOUND `elem` dirs)  $ threadWaitRead socket
      when (OUTBOUND `elem` dirs) $ threadWaitWrite socket

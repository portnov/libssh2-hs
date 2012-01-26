{-# LANGUAGE ForeignFunctionInterface, DeriveDataTypeable, FlexibleInstances, TypeFamilies #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Errors
  (-- * Types
   ErrorCode (..),
   NULL_POINTER,

   -- * Utilities
   CIntResult (..),

   -- * Functions
   getLastError,
   handleInt,
   handleNullPtr
  ) where

import Control.Exception
import Data.Generics
import Foreign
import Foreign.Ptr
import Foreign.C.Types

import Network.SSH.Client.LibSSH2.Types

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

class CIntResult a where
  type IntResult a

  intResult :: a -> CInt
  fromCInt :: a -> IntResult a

instance CIntResult CInt where
  type IntResult CInt = Int

  intResult = id
  fromCInt = fromIntegral

instance CIntResult CLong where
  type IntResult CLong = Int

  intResult = fromIntegral
  fromCInt = fromIntegral

instance (Integral i) => CIntResult (i, a) where
  type IntResult (i, a) = (Int, a)

  intResult (i, _) = fromIntegral i
  fromCInt (i, a) = (fromIntegral i, a)

instance CIntResult (CInt, a, b) where
  type IntResult (CInt, a, b) = (Int, a, b)

  intResult (i, _, _) = i
  fromCInt (i, a, b) = (fromIntegral i, a, b)

instance CIntResult (CInt, a, b, c) where
  type IntResult (CInt, a, b, c) = (Int, a, b, c)

  intResult (i, _, _, _) = i
  fromCInt (i, a, b, c) = (fromIntegral i, a, b, c)

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
handleInt :: (CIntResult a) => a -> IO (IntResult a)
handleInt x =
  if intResult x < 0
    then throw (int2error $ intResult x)
    else return (fromCInt x)

-- | Throw an exception if null pointer passed,
-- or return it casted to right type.
handleNullPtr :: (IsPointer a) => Ptr () -> IO a
handleNullPtr p
  | p == nullPtr = throw NULL_POINTER
  | otherwise    = return (fromPointer p)


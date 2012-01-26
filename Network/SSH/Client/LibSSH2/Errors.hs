{-# LANGUAGE DeriveDataTypeable, FlexibleInstances #-}

module Network.SSH.Client.LibSSH2.Erros where

import Control.Exception
import Data.Generics
import Foreign.C.Types

data SSH2Error =
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

instance Exception SSH2Error

error2int :: SSH2Error -> CInt
error2int = fromIntegral . negate . fromEnum

int2error :: CInt -> SSH2Error
int2error = toEnum . negate . fromIntegral

class IntResult a where
  intResult :: a -> CInt

instance IntResult CInt where
  intResult = id

instance IntResult (CInt, a) where
  intResult (i, _) = i

instance IntResult (CInt, a, b) where
  intResult (i, _, _) = i

instance IntResult (CInt, a, b, c) where
  intResult (i, _, _, _) = i

handleInt :: (IntResult a) => a -> IO a
handleInt x =
  if intResult x < 0
    then throw (int2error $ intResult x)
    else return x


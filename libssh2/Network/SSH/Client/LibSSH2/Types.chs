{-# LANGUAGE ForeignFunctionInterface, DeriveDataTypeable, StandaloneDeriving #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Types
  (Session,
   KnownHosts,
   Channel,
   ToPointer (..),
   CStringCLen,
   Size, SSize,
   withCStringLenIntConv,
   peekCStringPtr,
   peekMaybeCStringPtr,
   channelFromPointer,
   knownHostsFromPointer,
   sessionFromPointer,
   sessionGetSocket,
   sessionSetSocket,
   channelSession
  ) where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Data.Generics
import Data.IORef
import Network.Socket

type Size = {# type size_t #}

type SSize = {# type ssize_t #}

type CStringCLen i = (CString, i)

withCStringLenIntConv :: (Integral i) => String -> (CStringCLen i -> IO a) -> IO a
withCStringLenIntConv str fn =
  withCStringLen str (\(ptr, len) -> fn (ptr, fromIntegral len))

peekCStringPtr :: Ptr CString -> IO String
peekCStringPtr ptr = peekCAString =<< peek ptr

peekMaybeCStringPtr :: Ptr CString -> IO (Maybe String)
peekMaybeCStringPtr ptr = do
  strPtr <- peek ptr
  if strPtr == nullPtr
    then return Nothing
    else Just `fmap` peekCAString strPtr

class ToPointer p where
  toPointer :: p -> Ptr ()

{# pointer *SESSION as CSession #}

data Session = Session { sessionPtr       :: CSession
                       , sessionSocketRef :: IORef (Maybe Socket)
                       }

sessionFromPointer :: Ptr () -> IO Session
sessionFromPointer ptr = do
  socketRef <- newIORef Nothing
  return $ Session (castPtr ptr) socketRef

sessionGetSocket :: Session -> IO (Maybe Socket)
sessionGetSocket = readIORef . sessionSocketRef

sessionSetSocket :: Session -> Maybe Socket -> IO ()
sessionSetSocket session = writeIORef (sessionSocketRef session)

deriving instance Eq Session
deriving instance Data Session
deriving instance Typeable Session

instance Show Session where
  show session = "<libssh2 session: " ++ show (sessionPtr session) ++ ">"

instance ToPointer Session where
  toPointer = castPtr . sessionPtr 

{# pointer *KNOWNHOSTS as KnownHosts newtype #}

knownHostsFromPointer :: Ptr () -> IO KnownHosts
knownHostsFromPointer ptr = return $ KnownHosts (castPtr ptr)

deriving instance Eq KnownHosts
deriving instance Data KnownHosts
deriving instance Typeable KnownHosts

instance Show KnownHosts where
  show (KnownHosts p) = "<libssh2 known hosts: " ++ show p ++ ">"

instance ToPointer KnownHosts where
  toPointer (KnownHosts p) = castPtr p

{# pointer *CHANNEL as CChannel #}

data Channel = Channel { channelPtr     :: CChannel
                       , channelSession :: Session
                       }

channelFromPointer :: Session -> Ptr () -> IO Channel
channelFromPointer session ptr = return $ Channel (castPtr ptr) session

deriving instance Eq Channel
deriving instance Data Channel
deriving instance Typeable Channel

instance Show Channel where
  show channel = "<libssh2 channel: " ++ show (channelPtr channel) ++ ">"

instance ToPointer Channel where
  toPointer = castPtr . channelPtr 


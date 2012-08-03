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
   sessionFromPointer
  ) where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Data.Generics

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

{# pointer *SESSION as Session newtype #}

sessionFromPointer :: Ptr () -> Session
sessionFromPointer ptr = Session (castPtr ptr)

deriving instance Eq Session
deriving instance Data Session
deriving instance Typeable Session

instance Show Session where
  show (Session p) = "<libssh2 session: " ++ show p ++ ">"

instance ToPointer Session where
  toPointer (Session p) = castPtr p

{# pointer *KNOWNHOSTS as KnownHosts newtype #}

knownHostsFromPointer :: Ptr () -> KnownHosts
knownHostsFromPointer ptr = KnownHosts (castPtr ptr)

deriving instance Eq KnownHosts
deriving instance Data KnownHosts
deriving instance Typeable KnownHosts

instance Show KnownHosts where
  show (KnownHosts p) = "<libssh2 known hosts: " ++ show p ++ ">"

instance ToPointer KnownHosts where
  toPointer (KnownHosts p) = castPtr p

{# pointer *CHANNEL as Channel newtype #}

channelFromPointer :: Ptr () -> Channel
channelFromPointer ptr = Channel (castPtr ptr)

deriving instance Eq Channel
deriving instance Data Channel
deriving instance Typeable Channel

instance Show Channel where
  show (Channel p) = "<libssh2 channel: " ++ show p ++ ">"

instance ToPointer Channel where
  toPointer (Channel p) = castPtr p


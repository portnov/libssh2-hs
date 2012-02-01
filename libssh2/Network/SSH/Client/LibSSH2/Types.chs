{-# LANGUAGE ForeignFunctionInterface #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Types
  (Session,
   KnownHosts,
   Channel,
   IsPointer (..),
   CStringCLen,
   Size, SSize,
   withCStringLenIntConv,
   peekCStringPtr,
   peekMaybeCStringPtr
  ) where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String

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

class IsPointer p where
  fromPointer :: Ptr () -> p
  toPointer :: p -> Ptr ()

{# pointer *SESSION as Session newtype #}

instance IsPointer Session where
  fromPointer p = Session (castPtr p)
  toPointer (Session p) = castPtr p

{# pointer *KNOWNHOSTS as KnownHosts newtype #}

instance IsPointer KnownHosts where
  fromPointer p = KnownHosts (castPtr p)
  toPointer (KnownHosts p) = castPtr p

{# pointer *CHANNEL as Channel newtype #}

instance IsPointer Channel where
  fromPointer p = Channel (castPtr p)
  toPointer (Channel p) = castPtr p


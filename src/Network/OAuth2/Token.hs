{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.Token
    where

import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString as BS

import Data.Aeson
import Data.Aeson.Types
import Control.Applicative ((<$>),(<*>))
import Control.Monad (mzero, void)
import Control.Monad.IO.Class (liftIO)
import Control.Seq
import Data.Maybe

import Foreign
import Foreign.C
import Foreign.C.String
import Foreign.Ptr (Ptr,nullPtr)
import Foreign.Marshal.Alloc (free)
import Foreign.ForeignPtr.Safe

import System.IO

import Data.Time
import Data.Time.Clock.POSIX

foreign import ccall "StorePasswordKeychain" c_StorePasswordKeychain :: Ptr CChar -> Int -> Ptr CChar ->
                                                                        Int-> Ptr CChar -> Int -> Int
foreign import ccall "GetPasswordKeychain" c_GetPasswordKeychain :: Ptr a -> CUInt -> Ptr a ->
                                                                    CUInt -> CString
foreign import ccall "&ffree" ffree :: FunPtr (CString -> IO())

data Token = Token
    { authToken :: !String,
      expiresIn :: !Int,
      tokenType :: !String,
      refreshToken :: Maybe String,
      expires :: Double         -- Represented by POSIXTime in seconds
    } | Expired deriving (Show)

type PageToken = String

save :: Maybe Token -> String -> String -> IO ()
save Nothing _ _ = putStrLn "Cannot save Nothing"
save (Just tok) service account = do
  saveRefreshToken service account (refreshToken tok)
  BL.writeFile "token" encoded
    where
      encoded = Data.Aeson.encode tok

saveRefreshToken :: String -> String -> Maybe String -> IO ()
saveRefreshToken _ _ Nothing = hPutStrLn stderr "No refresh token to save!"
saveRefreshToken service account (Just pass) = do
  cService <- newCStringLen service
  cAccount <- newCStringLen account
  cPass <- newCStringLen pass

  newForeignPtr ffree (fst cService)
  newForeignPtr ffree (fst cAccount)
  newForeignPtr ffree (fst cPass)

  let result = c_StorePasswordKeychain svc svclen acct acctlen passwd passlen
          where
            (passwd, passlen) = cPass
            (svc, svclen) = cService
            (acct, acctlen) = cAccount

  putStrLn $ show result

fromKeychain :: String -> String -> IO (Maybe String)
fromKeychain service account = do
  cService <- newCStringLen service
  cAccount <- newCStringLen account

  newForeignPtr ffree (fst cService)
  newForeignPtr ffree (fst cAccount)

  let result = c_GetPasswordKeychain svc (fromIntegral svclen) acct (fromIntegral acctlen)
          where
            (svc, svclen) = cService
            (acct, acctlen) = cAccount
  newForeignPtr ffree result

  -- Convert from c-space to haskell space
  checkResult result

checkResult :: CString -> IO (Maybe String)
checkResult c_str
    | c_str == nullPtr = return Nothing
    | otherwise = do
                  result <- peekCString c_str
                  return $ Just result

decodeToken :: Maybe Object -> IO (Maybe Token)
decodeToken Nothing = return Nothing
decodeToken (Just result) = do
  let mt = flip parseMaybe result (\obj -> do
                                               accessToken <- obj .: "access_token"
                                               expiresIn <- obj .: "expires_in"
                                               tokenType <- obj .: "token_type"
                                               refreshToken <- obj .:? "refresh_token"
                                               return $ Token accessToken
                                                      expiresIn
                                                      tokenType
                                                      refreshToken
                                                      0.0)
  currentTime <- getPOSIXTime
  return $ fmap (\x -> x { expires = expiration currentTime mt }) mt
         where
           expiration now (Just token) = (realToFrac now :: Double) + validity token
           validity (token) = fromIntegral . expiresIn $ token

instance FromJSON Token where
    parseJSON (Object v) = Token <$>
                           v .: "access_token" <*>
                           v .: "expires_in" <*>
                           v .: "token_type" <*>
                           v .:? "refresh_token" <*>
                           v .:? "expires" .!= 0.0
    parseJSON _ = mzero

instance ToJSON Token where
    toJSON (Token accessToken expiresIn tokenType refreshToken expires) =
        object [ "access_token" .= accessToken,
                 "expires_in" .= expiresIn,
                 "token_type" .= tokenType,
                 "expires" .= expires
               ]

{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.OAuth2 (
               OAuth2WebServerFlow(localDirectory),
               createFlow,
	       endFlow,
               getTokens,
	       checkToken,
	       checkToken',
               refreshTokens,
	       getManager,
	       Flow,
	       getAuthToken
              )
    where

import Network.OAuth2.URI
import Network.OAuth2.CSRFToken
import Data.Aeson
import Data.Maybe
import Data.Monoid ((<>))
import Data.List (intercalate)
import Data.Maybe (fromJust)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Base (urlEncode)
import Network.HTTP.Types (hAuthorization)
import Network.HTTP.Types.Status (Status(..))
import Network.HTTP.Conduit
import Network.OAuth2.Token
import Text.Printf
import System.IO (hFlush, stdout)
import Network.HTTP.Conduit -- the main module
import Network.OAuth2.ConfigFile
import Control.Exception
import Control.Monad.Except
import Control.Monad.State
import Network.OAuth2.Util

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Char8 as C8

data OAuth2WebServerFlow = OAuth2WebServerFlow
    { token :: !CSRFToken,
      clientSecret :: !String,
      scope :: ![String],
      redirectUri :: !String,
      userAgent :: !String,
      authUri :: !String,
      tokenUri :: !String,
      revokeUri :: !String,
      loginHint :: !String,
      deviceUri :: !String,
      accessToken :: Maybe Token,
      manager :: Manager,
      localDirectory :: String,
      authService :: String,
      authAccount :: String
    }

type Flow = ExceptT String (StateT OAuth2WebServerFlow IO)

createFlow :: String -> String -> IO (OAuth2WebServerFlow)
createFlow configFile authorizationFile = do
  manager <- newManager conduitManagerSettings
  conf <- readConfig configFile
  authorization <- readConfig authorizationFile

  let oauthScope = [param "scopes" conf]
  let redirectUri = param "redirectUri" conf
  let userAgent = param "userAgent" conf
  let authUri = param "authUri" conf
  let deviceUri = param "deviceUri" conf
  let revokeUri = param "revokeUri" conf
  let tokenUri = param "tokenUri" conf
  let loginHint = param "loginHint" conf
  let clientId = param "clientId" conf
  let clientSecret = param "clientSecret" conf
  let localDirectory = param "localDirectory" conf
  let authService = param "authService" conf
  let authAccount = param "authAccount" conf

  return $ OAuth2WebServerFlow (CSRFToken clientId "someState" "drive")
         clientSecret oauthScope redirectUri
         userAgent authUri tokenUri revokeUri loginHint deviceUri Nothing manager localDirectory
	 authService authAccount

endFlow :: OAuth2WebServerFlow -> IO ()
endFlow = closeManager . manager
  
getManager :: OAuth2WebServerFlow -> Manager
getManager = manager

getAuthorizeUrl :: OAuth2WebServerFlow -> String
getAuthorizeUrl flow = request flow

getTokens :: Flow ()
getTokens = do
  webFlow <- get
  tok <- liftIO $ fromFile "token"
  case tok of
       Nothing -> do
       	       liftIO $ putStrLn "Requesting new tokens"
	       requestTokens'
       Just token -> do
       	    put $ webFlow {accessToken = token}
	    checkToken'

checkToken :: OAuth2WebServerFlow -> Maybe Token -> IO (Maybe Token)
checkToken flow Nothing = do
  putStrLn "Requesting new tokens"
  requestTokens flow
checkToken flow (Just token) = do
  currentTime <- getPOSIXTime
  if expires token > (realToFrac currentTime :: Double)
  then return $ Just token
  else do
    putStrLn "Token has expired. Requesting a new one"
    newToken <- refreshTokens flow (Just token)
    save newToken (authService flow) (authAccount flow)
    return newToken

checkToken' :: Flow ()
checkToken' = do
	   webFlow <- get
	   token <- liftIO $ getAuthToken webFlow
	   let expiration = expires token
	   currentTime <- liftIO getPOSIXTime
	   if expiration-60 > (realToFrac currentTime :: Double)
	   then put webFlow
	   else do
	   	liftIO $ putStrLn "Token has expired. Requesting a new one"
		newToken <- liftIO $ refreshTokens webFlow (Just token)
		liftIO $ save newToken (authService webFlow) (authAccount webFlow)
		put $ webFlow { accessToken = newToken }

refreshTokens :: OAuth2WebServerFlow -> Maybe Token -> IO (Maybe Token)
refreshTokens _ Nothing = return Nothing
refreshTokens flow (Just oldToken) = do
  -- refreshToken <- fromKeychain "My Google Drive" "MyDrive"
  refreshToken <- fromKeychain (authService flow) (authAccount flow)
  putStrLn "Refresh token is"

  let tok = token flow
  let params = [("client_id", clientId tok),
                ("client_secret", clientSecret flow),
                ("grant_type", "refresh_token"),
                ("refresh_token", fromJust $ refreshToken)
               ]

  fromUrl' flowManager (tokenUri flow) params >>= (\newToken -> return $ fst newToken)
    where
      flowManager = getManager flow

passRefreshToken :: Maybe Token -> Maybe String -> IO (Maybe Token)
passRefreshToken Nothing _ = return Nothing
passRefreshToken _ Nothing = return Nothing
passRefreshToken (Just newToken) refreshToken = do
  let result = Just $ newToken { refreshToken = refreshToken}
  return result

requestTokens :: OAuth2WebServerFlow -> IO (Maybe Token)
requestTokens flow = do
  let tok = token flow

  printf "\nVisit the following URL to retreive a verification code:\n\n"
  printf "%s\n\n" $ getAuthorizeUrl flow
  printf "Verification code: "
  hFlush stdout
  authCode <- getLine

  let params = [("client_id", clientId tok),
                ("client_secret", clientSecret flow),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirectUri flow),
                ("code", authCode)
               ]

  result <- fromUrl' flowManager (tokenUri flow) params
  save (fst result) (authService flow) (authAccount flow)
  return $ fst result
 where
   flowManager = getManager flow

requestTokens' :: Flow ()
requestTokens' = do
  webFlow <- get
  let tok = token webFlow
  let flowManager = getManager webFlow

  liftIO $ printf "\nVisit the following URL to retreive a verification code:\n\n"
  liftIO $ printf "%s\n\n" $ getAuthorizeUrl webFlow
  liftIO $ printf "Verification code: "
  liftIO $ hFlush stdout

  authCode <- liftIO $ getLine

  let params = [("client_id", clientId tok),
                ("client_secret", clientSecret webFlow),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirectUri webFlow),
                ("code", authCode)
               ]

  (result, status) <- liftIO $ fromUrl' flowManager (tokenUri webFlow) params
  liftIO $ save result (authService webFlow) (authAccount webFlow)
  put $ webFlow { accessToken = result }  

instance Show OAuth2WebServerFlow
    where
      show oauth = show $ clientId $ token oauth

instance URI OAuth2WebServerFlow
    where
      render flow = authUri flow
                    <>"?scope=" <> intercalate "+" (map urlEncode (scope flow))
                    <>"&redirect_uri="<>redirectUri flow
                    <>"&response_type=code"
                    <>"&client_id="<>clientId (token flow)

getAuthToken :: OAuth2WebServerFlow -> IO (Token)
getAuthToken flow = do
	       let tok = accessToken flow
	       case tok of
	       	    Nothing -> error "Invalid token for some reason."
		    Just token -> return token

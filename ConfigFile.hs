module ConfigFile (
                   Config,
                   readConfig,
                   param
                  ) where

import Data.Char
import Control.Monad
import qualified Data.Map as Map
import Text.ParserCombinators.Parsec
import Data.Either
import Data.Maybe
import System.Exit

type Config = Map.Map String String

ident :: Parser String
ident = do c <- letter <|> char '_'
           cs <- many (letter <|> digit <|> char '_')
           return (c:cs)
        <?> "identifier"

comment :: Parser ()
comment = do char '#'
             skipMany (noneOf "\r\n")
          <?> "comment"

eol :: Parser ()
eol = do oneOf "\n\r"
         return ()
      <?> "end of line"

item :: Parser (String, String)
item = do key <- ident
          skipMany space
          char ':'
          skipMany space
          value <- manyTill anyChar (try eol <|> try comment <|> eof)
          return (key, rstrip value)
              where rstrip = reverse . dropWhile isSpace . reverse

line :: Parser (Maybe (String, String))
line = do skipMany space
          try (comment >> return Nothing) <|> (item >>= return . Just)

file :: Parser [(String, String)]
file = do lines <- many line
          return (catMaybes lines)

fromLeft :: Either a b -> b
fromLeft (Right x) = x

readConfig_ :: SourceName -> IO (Either ParseError Config)
readConfig_ name =
    parseFromFile file name >>=
    return . fmap (foldr (uncurry Map.insert) Map.empty . reverse)

readConfig :: SourceName -> IO Config
readConfig name = do
  conf <- readConfig_ name
  return $ fromLeft $ conf

param :: (Ord k) => k -> Map.Map k a -> a
param k m = fromJust $ Map.lookup k m

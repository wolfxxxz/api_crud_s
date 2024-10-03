package middleware

import (
	"service_user/internal/apperrors"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
)

type JWTMiddlewareConfig struct {
	SecretKey string
}

func JWTAuthentication(jc *JWTMiddlewareConfig, blacklist *Blacklist) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := c.Request().Header.Get("Authorization")
			log.Error(tokenString)
			if tokenString == "" {
				appErr := apperrors.JWTMiddleware.AppendMessage("Missing token")
				return c.JSON(appErr.HTTPCode, appErr.Message)
			}

			if blacklist.IsTokenBlacklisted(tokenString) {
				appErr := apperrors.JWTMiddleware.AppendMessage("Token is blacklisted")
				log.Error(appErr)
				return c.JSON(appErr.HTTPCode, appErr.Message)
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					appErr := apperrors.JWTMiddleware.AppendMessage("invalid signature method")
					log.Error(appErr)
					return nil, appErr
				}

				return []byte(jc.SecretKey), nil
			})

			if err != nil {
				log.Error(err)
				appErr := apperrors.JWTMiddleware.AppendMessage("Token is invalidd")
				return c.JSON(appErr.HTTPCode, appErr.Message)
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				role, ok := claims["role"].(string)
				if !ok {
					appErr := apperrors.JWTMiddleware.AppendMessage("Role not found in token")
					return appErr
				}

				id, ok := claims["id"].(string)
				if !ok {
					appErr := apperrors.JWTMiddleware.AppendMessage("Id not found in token")
					return appErr
				}

				c.Set("role", role)
				c.Set("id", id)
				return next(c)
			}

			appErr := apperrors.JWTMiddleware.AppendMessage("The token has expired or is invalid")
			return c.JSON(appErr.HTTPCode, appErr.Message)
		}
	}
}

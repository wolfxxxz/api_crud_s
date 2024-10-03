package router

import (
	"service_user/internal/infrastructure/middleware"
	"service_user/internal/interface/controller"

	"github.com/labstack/echo"
	echoMiddleware "github.com/labstack/echo/middleware"
)

func NewRouter(e *echo.Echo, appController controller.AppController, secretKey string) *echo.Echo {
	e.Use(echoMiddleware.Logger())
	e.Use(echoMiddleware.Recover())

	e.POST("/users", appController.UserController.CreateUser)
	e.POST("/users/login", appController.UserController.Login)
	blackList := middleware.NewBlacklist()
	e.POST("/users/logout", appController.UserController.Logout(blackList))

	jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: secretKey}
	e.PUT("/users/:id", appController.UserController.UpdateUserByID, middleware.JWTAuthentication(&jwtConfig, blackList))
	e.PUT("/users/:id/password", appController.UserController.UpdateUserPasswordByID, middleware.JWTAuthentication(&jwtConfig, blackList))
	e.DELETE("/users/:id", appController.UserController.DropUserById, middleware.JWTAuthentication(&jwtConfig, blackList))
	e.PUT("/users/:voter_user_id/vote", appController.UserController.VoteUser, middleware.JWTAuthentication(&jwtConfig, blackList))
	e.GET("/users/pagination", appController.UserController.GetUsersByPagination)
	e.GET("/users/:id", appController.UserController.GetUserById)

	return e
}

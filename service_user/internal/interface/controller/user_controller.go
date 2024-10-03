package controller

import (
	"net/http"
	"service_user/internal/apperrors"
	"service_user/internal/config"
	"service_user/internal/domain/requests"
	"service_user/internal/infrastructure/middleware"
	"service_user/internal/usecase/interactor"

	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type userController struct {
	userInteractor interactor.UserInteractor
	log            *logrus.Logger
	config         *config.Config
}

type UserController interface {
	CreateUser(c echo.Context) error
	GetUsersByPagination(c echo.Context) error
	GetUserById(c echo.Context) error

	Login(c echo.Context) error
	UpdateUserByID(c echo.Context) error
	UpdateUserPasswordByID(c echo.Context) error
	DropUserById(c echo.Context) error
	Logout(blacklist *middleware.Blacklist) echo.HandlerFunc
	VoteUser(c echo.Context) error
}

func NewUserController(us interactor.UserInteractor, log *logrus.Logger, config *config.Config) UserController {
	return &userController{us, log, config}
}

func (uc *userController) VoteUser(c echo.Context) error {
	voterUserID := c.Param("voter_user_id")
	if voterUserID == "" {
		appErr := apperrors.ControllerVoteUserErr.AppendMessage("voter_user_id is empty")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	var voteRequest requests.VoteRequest
	if err := c.Bind(&voteRequest); err != nil {
		appErr := apperrors.ControllerVoteUserBindErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	if err := c.Validate(voteRequest); err != nil {
		return err
	}

	votedUserID := c.Get("id").(string)
	err := uc.userInteractor.VoteUser(c.Request().Context(), votedUserID, voterUserID, &voteRequest)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusOK, "success")
}

func (uc *userController) Logout(blacklist *middleware.Blacklist) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			appErr := apperrors.JWTMiddleware.AppendMessage("LOGOUT_ERR: Missing token")
			uc.log.Error(appErr)
			return c.JSON(appErr.HTTPCode, appErr.Message)
		}

		blacklist.AddToken(token)
		return c.JSON(http.StatusOK, "token deleted")
	}
}

func (uc *userController) CreateUser(c echo.Context) error {
	var createUserRequest requests.CreateUserRequest
	if err := c.Bind(&createUserRequest); err != nil {
		appErr := apperrors.ControllerCreateUserErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	if err := c.Validate(createUserRequest); err != nil {
		return err
	}

	userIdResponse, err := uc.userInteractor.CreateUser(c.Request().Context(), &createUserRequest)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusCreated, userIdResponse)
}

func (uc *userController) GetUsersByPagination(c echo.Context) error {
	page := c.QueryParam("page")
	perPage := c.QueryParam("per_page")
	if page == "" || perPage == "" {
		appErr := apperrors.ControllerGetUsersByPaginationError.AppendMessage("page, per_page err")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	responseUsers, err := uc.userInteractor.GetUsersByPageAndPerPage(c.Request().Context(), page, perPage)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HttpCode(), appErr.Error())
	}

	return c.JSON(http.StatusOK, responseUsers)
}

func (uc *userController) GetUserById(c echo.Context) error {
	userId := c.Param("id")
	if userId == "" {
		appErr := apperrors.ControllerGetUserByIdErr.AppendMessage("user_id is empty")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	getUsersByIdResponse, err := uc.userInteractor.GetUserByID(c.Request().Context(), userId)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusOK, getUsersByIdResponse)
}

func (uc *userController) Login(c echo.Context) error {
	var loginRequest requests.LoginRequest
	if err := c.Bind(&loginRequest); err != nil {
		appErr := apperrors.ControllerLoginErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	if err := c.Validate(loginRequest); err != nil {
		return err
	}

	tokenResponse, err := uc.userInteractor.SignInUserWithJWT(c.Request().Context(), &loginRequest, uc.config.SecretKey, uc.config.ExpirationJWTInSeconds)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	uc.log.Info("token was sended")
	return c.JSON(http.StatusOK, tokenResponse)
}

func (uc *userController) UpdateUserByID(c echo.Context) error {
	userId := c.Param("id")
	if userId == "" {
		appErr := apperrors.ControllerUpdateUserByIdErr.AppendMessage("user_id is empty")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	var updateUserRequest requests.UpdateUserRequest
	if err := c.Bind(&updateUserRequest); err != nil {
		appErr := apperrors.ControllerUpdateUserByIDRequestErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	updateUserRequest.ID = userId

	if err := c.Validate(updateUserRequest); err != nil {
		return err
	}

	role := c.Get("role").(string)
	authID := c.Get("id").(string)
	userEmailResponse, err := uc.userInteractor.UpdateUserByID(c.Request().Context(), &updateUserRequest, authID, role)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusOK, userEmailResponse)
}

func (uc *userController) UpdateUserPasswordByID(c echo.Context) error {
	userId := c.Param("id")
	if userId == "" {
		appErr := apperrors.ControllerUpdateUserPasswordByIdErr.AppendMessage("user_id is empty")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	var updateUserPasswordRequest requests.UpdateUserPasswordRequest
	if err := c.Bind(&updateUserPasswordRequest); err != nil {
		appErr := apperrors.ControllerUpdateUserPasswordByIDErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	updateUserPasswordRequest.ID = userId

	if err := c.Validate(updateUserPasswordRequest); err != nil {
		return err
	}

	authID := c.Get("id").(string)
	updatedUserEmail, err := uc.userInteractor.UpdateUserPasswordByID(c.Request().Context(), &updateUserPasswordRequest, authID)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusOK, updatedUserEmail)
}

func (uc *userController) DropUserById(c echo.Context) error {
	userId := c.Param("id")
	if userId == "" {
		appErr := apperrors.ControllerDropUserByIDErr.AppendMessage("user_id is empty")
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	var dropUserRequest requests.DeleteUserRequest
	if err := c.Bind(&dropUserRequest); err != nil {
		appErr := apperrors.ControllerLoginErr.AppendMessage(err)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Message)
	}

	if err := c.Validate(dropUserRequest); err != nil {
		return err
	}

	role := c.Get("role").(string)
	authID := c.Get("id").(string)
	err := uc.userInteractor.DropUserByID(c.Request().Context(), userId, authID, role)
	if err != nil {
		appErr := err.(*apperrors.AppError)
		uc.log.Error(appErr)
		return c.JSON(appErr.HTTPCode, appErr.Error())
	}

	return c.JSON(http.StatusOK, "the user has been deleted")
}

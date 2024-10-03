package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"service_user/internal/apperrors"
	"service_user/internal/config"
	"service_user/internal/domain/mappers"
	"service_user/internal/domain/models"
	"service_user/internal/domain/requests"
	"service_user/internal/domain/responses"
	"service_user/internal/domain/validator"
	"service_user/internal/infrastructure/middleware"
	"service_user/internal/mock"
	"service_user/internal/usecase/interactor"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func getToken(t *testing.T, user *models.User) (string, error) {
	log := logrus.New()
	passwordHash, err := hashPassword("new_secure_password")
	if err != nil {
		log.Error(err)
		return "", err
	}

	ctrl := gomock.NewController(t)
	userRepoMock := mock.NewMockUserRepository(ctrl)

	ctx := context.Background()
	userWithHashPassword := mappers.MapToUser(user.Email, user.UserName, user.FirstName, user.LastName, passwordHash, user.Role)
	userRepoMock.EXPECT().GetUserByEmail(ctx, gomock.Any()).Return(userWithHashPassword, nil).AnyTimes()
	inputUserReq := []byte(`{
				"email": "Tooken@Admin.com",
				"password": "new_secure_password"
			}`)

	uInteractor := interactor.NewUserInteractor(userRepoMock)
	cfg := config.Config{SecretKey: "secret", ExpirationJWTInSeconds: "250"}
	uController := NewUserController(uInteractor, log, &cfg)

	e := echo.New()
	v := validator.NewValidator(log)
	e.Validator = v

	req := httptest.NewRequest(http.MethodPut, "/users/login", bytes.NewBuffer(inputUserReq))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err = uController.Login(c)
	if err != nil {
		return "", err
	}

	var tokenResponse responses.LoginResponse
	err = json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.Token, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", apperrors.HashPasswordErr.AppendMessage(err)
	}

	return string(bytes), nil
}

func getTokenPasswordSuccess(t *testing.T, user *models.User) (string, error) {
	log := logrus.New()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	userRepoMock := mock.NewMockUserRepository(ctrl)
	userRepoMock.EXPECT().GetUserByEmail(ctx, gomock.Any()).Return(user, nil).AnyTimes()
	inputUserReq := []byte(`{
				"email": "Tooken@Admin.com",
				"password": "new_secure_password"
			}`)

	uInteractor := interactor.NewUserInteractor(userRepoMock)
	config := config.Config{SecretKey: "secret", ExpirationJWTInSeconds: "250"}
	uController := NewUserController(uInteractor, log, &config)
	e := echo.New()
	v := validator.NewValidator(log)
	e.Validator = v
	req := httptest.NewRequest(http.MethodPut, "/users/login", bytes.NewBuffer(inputUserReq))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := uController.Login(c)
	if err != nil {
		return "", err
	}

	var tokenResponse responses.LoginResponse
	json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
	return tokenResponse.Token, nil
}

func TestGetUserById(t *testing.T) {
	user := mappers.MapToUser("hello@hello.com", "John_Snow", "John", "Targaryen", "password", "user")
	userId := user.ID.String()
	reqBodyBindErr := []byte(`{
		"user_id": "a700ce3c-e29a-4523-af3b-ff75d8ab40a5"
	}`)
	reqBody := []byte(`{
	    "user_id": "a700ce3c-e29a-4523-af3b-ff75d8ab40a5"
	}`)
	testTable := []struct {
		scenario         string
		inputUserRequest []byte
		inputUserID      string
		expectedUser     *models.User
		contentType      string
		expectedUserID   string
		response         interface{}
		httpCode         int
		expectedError    error
	}{
		{
			"get user wrong params err",
			reqBodyBindErr,
			"",
			nil,
			echo.MIMEApplicationXML,
			"",
			apperrors.ControllerGetUserByIdErr.AppendMessage("user_id is empty").Message,
			apperrors.ControllerGetUserByIdErr.HTTPCode,
			&apperrors.ControllerGetUserByIdErr,
		},
		{
			"user not found by id",
			reqBody,
			"a700ce3c-e29a-4523-af3b-ff75d8ab40a5",
			user,
			echo.MIMEApplicationJSON,
			userId,
			"USER_REPO_ERR: Failed GetUserByID",
			http.StatusNotFound,
			&apperrors.MongoGetUserByIDErr,
		},
		{
			"get one user by id positive",
			reqBody,
			"a700ce3c-e29a-4523-af3b-ff75d8ab40a5",
			user,
			echo.MIMEApplicationJSON,
			userId,
			*mappers.MapUserToGetUserByIdResponse(user),
			http.StatusOK,
			nil,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			log := logrus.New()
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodGet, "/users/:id", bytes.NewBuffer(tc.inputUserRequest))
			req.Header.Set(echo.HeaderContentType, tc.contentType)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tc.inputUserID)
			userRepoMock.EXPECT().GetUserByID(c.Request().Context(), gomock.Any()).Return(tc.expectedUser, tc.expectedError).AnyTimes()
			err := uController.GetUserById(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestGetUsersByPagination(t *testing.T) {
	user := mappers.MapToUser("hello@hello.com", "John_Snow", "John", "Targaryen", "password", "user")
	userTwo := mappers.MapToUser("hello@hello.com", "John_Snow", "John", "Targaryen", "password", "user")
	users := []*models.User{user, userTwo}
	testTable := []struct {
		scenario          string
		expectedUser      []*models.User
		inputPage         string
		inputPerPage      string
		queryParamPage    string
		gueryParamPerPage string
		response          interface{}
		httpCode          int
		expectedError     error
	}{
		{
			"wrong parameter perPage",
			nil,
			"1",
			"10",
			"page",
			"perPage",
			"Failed GetUsersByPagination : [page, per_page err]",
			http.StatusBadRequest,
			&apperrors.ControllerGetUsersByPaginationError,
		},
		{
			"wrong parameters page, per_page",
			nil,
			"1",
			"10",
			"page",
			"per_page",
			"Controller_Err: Failed GetUsersByPagination",
			http.StatusBadRequest,
			&apperrors.ControllerGetUsersByPaginationError,
		},
		{
			"get users by pagination success",
			users,
			"130",
			"100500",
			"page",
			"per_page",
			mappers.MapUsersToGetUsersByPaginationResponse(users, "130", "100500"),
			http.StatusOK,
			nil,
		},
		{
			"get users by pagination success",
			users,
			"1",
			"10",
			"page",
			"per_page",
			mappers.MapUsersToGetUsersByPaginationResponse(users, "1", "10"),
			http.StatusOK,
			nil,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			pageNum, err := strconv.Atoi(tc.inputPage)
			if err != nil {
				t.Error(err)
				return
			}

			perPageNum, err := strconv.Atoi(tc.inputPerPage)
			if err != nil {
				t.Error(err)
				return
			}

			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().GetUsersByPageAndPerPage(ctx, pageNum,
				perPageNum).Return(tc.expectedUser, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			log := logrus.New()
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/users/pagination", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.QueryParams().Add(tc.queryParamPage, tc.inputPage)
			c.QueryParams().Add(tc.gueryParamPerPage, tc.inputPerPage)
			err = uController.GetUsersByPagination(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	reqBodyBindErr := []byte(`{
			"email": "hello@john.com",
			"user_name": "John_Snow",
			"first_name": "John",
			"password": "Targaryen",
			"role": "user"
		}`)

	reqBody := []byte(`{
			"email": "hello@john.com",
			"user_name": "John_Snow",
			"first_name": "John",
			"last_name": "Snow",
			"password": "Targaryen",
			"role": "user"
		}`)

	reqBodyInValid := []byte(`{
			"user_name": "John_Snow",
			"first_name": "John",
			"last_name": "Snow",
			"password": "Targaryen",
			"role": "user"
		}`)

	createUserRequest := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "Targaryen",
	}

	log := logrus.New()
	user, err := mappers.MapCreateUserRequestToUser(&createUserRequest)
	if err != nil {
		log.Error(err)
	}

	UUID, err := uuid.Parse("0ae29b28-b33e-4590-955d-74e205b80e93")
	user.ID = &UUID
	if err != nil {
		log.Error(err)
	}

	testTable := []struct {
		scenario      string
		inputUserReq  []byte
		user          *models.User
		contentType   string
		response      interface{}
		httpCode      int
		expectedError error
	}{
		{
			"create user bind err",
			reqBodyBindErr,
			user,
			echo.MIMEApplicationXML,
			"Failed CreateUser : [code=400, message=EOF]",
			http.StatusBadRequest,
			&apperrors.ControllerCreateUserErr,
		},
		{
			"create user - wrong params",
			reqBodyInValid,
			user,
			echo.MIMEApplicationJSON,
			"wrong params",
			http.StatusBadRequest,
			&apperrors.ValidateErr,
		},
		{
			"create user positive",
			reqBody,
			user,
			echo.MIMEApplicationJSON,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			http.StatusCreated,
			nil,
		},
		{
			"create user negative",
			reqBody,
			user,
			echo.MIMEApplicationJSON,
			"Map_Create_User_Request_To_User_Err: Create User Err",
			http.StatusBadRequest,
			&apperrors.MapCreateUserRequestToUserErr,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, tc.contentType)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			userRepoMock.EXPECT().CreateUser(c.Request().Context(), gomock.Any()).Return(tc.user.ID.String(), tc.expectedError).AnyTimes()
			err := uController.CreateUser(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestUpdateUserByIDPositive(t *testing.T) {
	log := logrus.New()
	reqUserLogin := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "secret_password",
		Role:      "admin",
	}

	userSuccess, err := mappers.MapCreateUserRequestToUser(&reqUserLogin)
	if err != nil {
		log.Error(err)
		return
	}

	realToken, err := getToken(t, userSuccess)
	if err != nil {
		log.Error(err)
		return
	}
	reqBody := []byte(`{
		"user_id": "de355b73-d3e6-407e-89c0-f38f5701ae43",
		"email": "hello@john.com",
		"user_name": "John_Snow",
		"first_name": "John",
		"last_name": "Snow"
	}`)
	reqUser := requests.UpdateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
	}

	user, _ := mappers.MapUpdateUserRequestToUser(&reqUser)
	testTable := []struct {
		scenario      string
		role          string
		response      string
		inputUserReq  []byte
		inputUserID   string
		user          *models.User
		httpCode      int
		expectedError error
		authorization string
	}{
		{
			"update user positive",
			"user",
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			reqBody,
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			user,
			http.StatusOK,
			nil,
			realToken,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().UpdateUserByID(ctx, gomock.Any()).Return(tc.inputUserID, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPut, "/users", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tc.inputUserID)
			jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: config.SecretKey}
			blacklist := middleware.NewBlacklist()
			JWTAuthFunc := middleware.JWTAuthentication(&jwtConfig, blacklist)
			handlerWithMiddleware := JWTAuthFunc(uController.UpdateUserByID)
			err := handlerWithMiddleware(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestUpdateUserByID(t *testing.T) {
	log := logrus.New()
	reqUserLogin := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "secret_password",
		Role:      "admin",
	}

	userSuccess, err := mappers.MapCreateUserRequestToUser(&reqUserLogin)
	if err != nil {
		log.Error(err)
		return
	}

	realToken, err := getToken(t, userSuccess)
	if err != nil {
		log.Error(err)
		return
	}

	reqBody := []byte(`{
			"user_id": "de355b73-d3e6-407e-89c0-f38f5701ae43",
			"email": "hello@john.com",
			"user_name": "John_Snow",
			"first_name": "John",
			"last_name": "Snow"
		}`)
	reqBodyUUID := []byte(`{
			"user_id": "fdfgdgdfdf",
			"email": "hello@john.com",
			"user_name": "John_Snow",
			"first_name": "John",
			"last_name": "Snow"
		}`)
	reqBodyInValid := []byte(`{

		"user_name": "John_Snow",
		"first_name": "John",
		"last_name": "Snow"
	}`)
	reqBodyInValid2 := []byte(`{
			"email": "hello@john.com",
			"user_name": "John_Snow",
			"first_name": "John",
			"last_name": "Snow"
		}`)
	reqUser := requests.UpdateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
	}

	user, _ := mappers.MapUpdateUserRequestToUser(&reqUser)
	testTable := []struct {
		scenario      string
		role          string
		response      string
		inputUserReq  []byte
		inputUserID   string
		user          *models.User
		httpCode      int
		expectedError error
		authorization string
	}{
		{
			"request id is empty",
			"user",
			"Failed UpdateUserByID : [user_id is empty]",
			nil,
			"",
			nil,
			apperrors.ControllerUpdateUserByIdErr.HTTPCode,
			apperrors.ControllerUpdateUserByIdErr.AppendMessage("user_id is empty"),
			realToken,
		},
		{
			"request body is empty",
			"user",
			"Failed UpdateUserByID : [code=400, message=Request body can't be empty]",
			nil,
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			nil,
			apperrors.ControllerUpdateUserByIDRequestErr.HTTPCode,
			&apperrors.ControllerUpdateUserByIDRequestErr,
			realToken,
		},
		{
			"validate err",
			"user",
			"Validate_Err: Validate Err : [Key: 'UpdateUserRequest.Email' Error:Field validation for 'Email' failed on the 'required' tag]",
			reqBodyInValid,
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			nil,
			http.StatusBadRequest,
			apperrors.ValidateErr.AppendMessage("Key: 'UpdateUserRequest.Email' Error:Field validation for 'Email' failed on the 'required' tag"),
			realToken,
		},
		{
			"request error",
			"user",
			"User_Interfactor_Err: Failed UpdateUserByID CoverstionToUUID",
			reqBodyInValid2,
			"sdjbdklsdjk4566",
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
			realToken,
		},
		{
			"update user unauthorized",
			"user",
			"Controller_Err: Failed UpdateUserByID : [unauthorized]",
			reqBody,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			nil,
			http.StatusForbidden,
			apperrors.ControllerUpdateUserByIDErr.AppendMessage("unauthorized"),
			realToken,
		},
		{
			"update user UUID Body is broken",
			"admin",
			"User_Interfactor_Err: Failed UpdateUserByID CoverstionToUUID",
			reqBodyUUID,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			user,
			http.StatusBadRequest,
			&apperrors.CoverstionToUUIDFailedUpdateUserByID,
			realToken,
		},
		{
			"update user positive",
			"user",
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			reqBody,
			"de355b73-d3e6-407e-89c0-f38f5701ae43",
			user,
			http.StatusOK,
			nil,
			realToken,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().UpdateUserByID(ctx, gomock.Any()).Return(tc.inputUserID, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			cfg := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &cfg)

			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v

			req := httptest.NewRequest(http.MethodPut, "/users/:id", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("Authorization", tc.authorization)

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tc.inputUserID)

			jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: cfg.SecretKey}
			blacklist := middleware.NewBlacklist()
			JWTAuthFunc := middleware.JWTAuthentication(&jwtConfig, blacklist)
			handlerWithMiddleware := JWTAuthFunc(uController.UpdateUserByID)
			err := handlerWithMiddleware(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestUpdateUserPasswordByID(t *testing.T) {
	log := logrus.New()
	reqUserLogin := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "secret_password",
		Role:      "admin",
	}

	userSuccess, err := mappers.MapCreateUserRequestToUser(&reqUserLogin)
	if err != nil {
		log.Error(err)
		return
	}

	passwordHash, err := hashPassword("new_secure_password")
	if err != nil {
		log.Error(err)
		return
	}

	userSuccess.Password = passwordHash

	userUUID, err := uuid.Parse("0ae29b28-b33e-4590-955d-74e205b80e93")
	if err != nil {
		return
	}

	userSuccess.ID = &userUUID

	realToken, err := getTokenPasswordSuccess(t, userSuccess)
	if err != nil {
		log.Error(err)
		return
	}

	reqBodyInValid := []byte(`{

		"password": "new_secure_password"
	  }`)
	reqBodyInValid2 := []byte(`{

		"password": "new_secure_password"
	  }`)
	reqBodyUnauth := []byte(`{
			"user_id": "0ae29b28-b33e-4590-955d-74e205b80e",
			"existing_password": "scret_password",
			"password": "new_secure_password"
		  }`)

	reqBody := []byte(`{
			"user_id": "0ae29b28-b33e-4590-955d-74e205b80e93",
			"existing_password": "secret_password",
			"password": "new_secure_password"
		  }`)
	reqUserPassword := requests.UpdateUserPasswordRequest{
		ID:               "0ae29b28-b33e-4590-955d-74e205b80e93",
		NewPassword:      "new_secure_password",
		ExistingPassword: "secret_password",
	}
	user, _ := mappers.MapUpdateUserPasswordRequestToUser(&reqUserPassword)
	testTable := []struct {
		scenario      string
		role          string
		response      interface{}
		inputUserReq  []byte
		inputUserID   string
		authorization string
		user          *models.User
		httpCode      int
		expectedError error
	}{
		{
			"request id is emptyy",
			"user",
			apperrors.ControllerUpdateUserPasswordByIdErr.AppendMessage("user_id is empty").Message,
			nil,
			"",
			realToken,
			nil,
			apperrors.ControllerUpdateUserPasswordByIdErr.HTTPCode,
			apperrors.ControllerUpdateUserPasswordByIdErr.AppendMessage("user_id is empty"),
		},
		{
			"request body is empty",
			"user",
			"Failed UpdateUserPasswordByID : [code=400, message=Request body can't be empty]",
			nil,
			"sdjbdklsdjk4566",
			realToken,
			nil,
			http.StatusUnauthorized,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"validate err",
			"user",
			"User_Interfactor_Err: Failed UpdateUserPasswordByID",
			reqBodyInValid,
			"sdjbdklsdjk4566",
			realToken,
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"request error",
			"user",
			"User_Interfactor_Err: Failed UpdateUserPasswordByID",
			reqBodyInValid2,
			"sdjbdklsdjk4566",
			realToken,
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"update user unauthorized",
			"user",
			"User_Interfactor_Err: Failed UpdateUserPasswordByID : [unauthorized]",
			reqBodyUnauth,
			"0ae29b28-b33e-4590-955d-74e205b80e95",
			realToken,
			nil,
			http.StatusForbidden,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"update user password success",
			"user",
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			reqBody,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			realToken,
			user,
			http.StatusOK,
			nil,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().UpdateUserPasswordByID(ctx, gomock.Any()).Return(tc.inputUserID, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPut, "/users/:id/password", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tc.inputUserID)

			jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: config.SecretKey}
			blacklist := middleware.NewBlacklist()
			JWTAuthFunc := middleware.JWTAuthentication(&jwtConfig, blacklist)
			handlerWithMiddleware := JWTAuthFunc(uController.UpdateUserPasswordByID)
			err := handlerWithMiddleware(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestLoginPositive(t *testing.T) {
	log := logrus.New()
	reqBody := []byte(`{
		"email": "Tooken@Admin.com",
		"password": "new_secure_password"
	}`)
	password, err := hashPassword("new_secure_password")
	if err != nil {
		log.Error(err)
	}

	user := mappers.MapToUser("Tooken@Admin.com", "first", "john", "black", password, "user")

	testTable := []struct {
		scenario      string
		role          string
		response      interface{}
		inputUserReq  []byte
		inputUserID   string
		authorization string
		user          *models.User
		httpCode      int
		expectedError error
	}{
		{
			"login positive",
			"admin",
			"jwt",
			reqBody,
			"",
			"",
			user,
			http.StatusOK,
			nil,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().GetUserByEmail(ctx, gomock.Any()).Return(tc.user, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret", ExpirationJWTInSeconds: "250"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPut, "/users/login", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			err := uController.Login(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			var tokenResponse responses.LoginResponse
			json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
			log.Infof("TOKEN [%v]", tokenResponse.Token)
			if assert.NoError(t, err) {
				assert.Equal(t, tc.response, tokenResponse.TokenType)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	reqBodyInValid := []byte(`{
			"email": "TookenAdmin.com",
			"password": "new_secure_password"
		}`)
	reqBodyInValid2 := []byte(`{
			"email": "Tooken@Admin.com",
			"password": "new_secure_password"
		}`)
	log := logrus.New()
	testTable := []struct {
		scenario      string
		role          string
		response      interface{}
		inputUserReq  []byte
		inputUserID   string
		authorization string
		user          *models.User
		httpCode      int
		expectedError error
	}{
		{
			"request body is empty",
			"",
			"Failed Login : [code=400, message=Request body can't be empty]",
			nil,
			"sdjbdklsdjk4566",
			"",
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"validate err",
			"",
			"User_Interfactor_Err: Failed UpdateUserPasswordByID",
			reqBodyInValid,
			"sdjbdklsdjk4566",
			"",
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"request error",
			"",
			"Controller_Err: Failed UpdateUserByID",
			reqBodyInValid2,
			"sdjbdklsdjk4566",
			"",
			nil,
			http.StatusConflict,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().GetUserByEmail(ctx, gomock.Any()).Return(tc.user, tc.expectedError).AnyTimes()
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret", ExpirationJWTInSeconds: "250"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPut, "/users/login", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set("role", tc.role)
			c.Set("id", tc.inputUserID)
			err := uController.Login(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			log.Info(t, string(marshalledResponse))
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestLogout(t *testing.T) {
	log := logrus.New()
	testTable := []struct {
		scenario      string
		response      interface{}
		authorization string
		httpCode      int
		expectedError error
	}{
		{
			"auth header is empty",
			"JWT Middleware : [LOGOUT_ERR: Missing token]",
			"",
			http.StatusUnauthorized,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"token deleted positive",
			"token deleted",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTk2OTcyNjMsImlkIjoiZWE3ZTJkY2YtZjBlYi00YTYyLWJhZWItNzM2MjcxODcyNzMyIiwicm9sZSI6ImFkbWluIn0.ZbKQJhvqex9ii8C0QB5HDkAKD958Q0IR73Y81P4bWp4",
			http.StatusOK,
			nil,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret", ExpirationJWTInSeconds: "250"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPost, "/users/logout", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			blackList := middleware.NewBlacklist()
			err := uController.Logout(blackList)(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestDropUserByID(t *testing.T) {
	log := logrus.New()
	reqUserLogin := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "secret_password",
		Role:      "admin",
	}

	userSuccess, err := mappers.MapCreateUserRequestToUser(&reqUserLogin)
	if err != nil {
		log.Error(err)
		return
	}

	log.Info(userSuccess.ID.String())

	realToken, err := getToken(t, userSuccess)
	if err != nil {
		log.Error(err)
		return
	}

	reqBodyBindErr := []byte(`{
		"user_d": "16a62bef-72e9-4e5c-976b-5633b14109b7"
	}`)
	reqBody := []byte(`{
	    "user_id": "16a62bef-72e9-4e5c-976b-5633b14109b7"
	}`)
	testTable := []struct {
		scenario         string
		inputUserRequest []byte
		role             string
		response         string
		contentType      string
		inputUserID      string
		httpCode         int
		expectedError    error
		authorization    string
	}{
		{
			"request id is empty",
			reqBodyBindErr,
			"user",
			"Failed DropUserByID : [user_id is empty]",
			echo.MIMEApplicationXML,
			"",
			http.StatusBadRequest,
			&apperrors.ControllerDropUserByIDErr,
			realToken,
		},
		{
			"bind err wrong content type",
			reqBodyBindErr,
			"admin",
			"Failed Login : [code=400, message=EOF]",
			echo.MIMEApplicationXML,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			apperrors.ControllerLoginErr.HTTPCode,
			&apperrors.ControllerLoginErr,
			realToken,
		},
		{
			"validate err ",
			reqBodyBindErr,
			"admin",
			"Failed Login : [code=400, message=EOF]",
			echo.MIMEApplicationJSON,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			apperrors.ControllerLoginErr.HTTPCode,
			&apperrors.ControllerLoginErr,
			realToken,
		},
		{
			"not enough rights",
			reqBody,
			"user",
			"Controller_Err: Failed DropUserByID : [not enough rigths, role is wrong]",
			echo.MIMEApplicationJSON,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			http.StatusBadRequest,
			apperrors.ControllerDropUserByIDErr.AppendMessage("not enough rigths, role is wrong"),
			realToken,
		},
		{
			"delete user positive",
			reqBody,
			"admin",
			"the user has been deleted",
			echo.MIMEApplicationJSON,
			"0ae29b28-b33e-4590-955d-74e205b80e93",
			http.StatusOK,
			nil,
			realToken,
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodDelete, "/users/:id", bytes.NewBuffer(tc.inputUserRequest))
			req.Header.Set(echo.HeaderContentType, tc.contentType)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(tc.inputUserID)

			userRepoMock.EXPECT().DropUserByID(c.Request().Context(), gomock.Any()).Return(tc.expectedError).AnyTimes()
			jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: config.SecretKey}
			blacklist := middleware.NewBlacklist()
			JWTAuthFunc := middleware.JWTAuthentication(&jwtConfig, blacklist)
			handlerWithMiddleware := JWTAuthFunc(uController.DropUserById)
			err := handlerWithMiddleware(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

func TestVoteUser(t *testing.T) {
	log := logrus.New()
	reqUserLogin := requests.CreateUserRequest{
		Email:     "hello@john.com",
		UserName:  "John_Snow",
		FirstName: "John",
		LastName:  "Snow",
		Password:  "secret_password",
		Role:      "admin",
	}

	userSuccess, err := mappers.MapCreateUserRequestToUser(&reqUserLogin)
	if err != nil {
		log.Error(err)
		return
	}

	passwordHash, err := hashPassword("new_secure_password")
	if err != nil {
		log.Error(err)
		return
	}

	userSuccess.Password = passwordHash
	userUUID, err := uuid.Parse("0ae29b28-b33e-4590-955d-74e205b80e93")
	if err != nil {
		return
	}

	userSuccess.ID = &userUUID
	token, err := getToken(t, userSuccess)
	if err != nil {
		log.Error(err)
		return
	}

	reqBodyInValid := []byte(`{
		"vote_valu": "-1"
	  }`)
	reqBody := []byte(`{
		"vote_value":"-1"
	  }`)
	userVoted := models.User{ID: userSuccess.ID, Email: "first"}
	userId2 := uuid.New()
	userVotes := models.User{ID: &userId2, Email: "second"}
	testTable := []struct {
		scenario      string
		role          string
		response      interface{}
		inputUserReq  []byte
		inputUserID   string
		authorization string
		userVoted     *models.User
		userVotes     *models.User
		httpCode      int
		expectedError error
	}{
		{
			"request id is empty",
			"user",
			apperrors.ControllerVoteUserBindErr.AppendMessage("voter_user_id is empty").Message,
			nil,
			"",
			token,
			nil,
			nil,
			apperrors.ControllerVoteUserBindErr.HTTPCode,
			apperrors.ControllerVoteUserBindErr.AppendMessage("user_id is empty"),
		},
		{
			"request body is empty",
			"user",
			apperrors.ControllerVoteUserBindErr.AppendMessage("code=400, message=Request body can't be empty").Message,
			nil,
			"sdjbdklsdjk4566",
			token,
			nil,
			nil,
			apperrors.ControllerVoteUserBindErr.HTTPCode,
			&apperrors.ControllerVoteUserBindErr,
		},
		{
			"validate err",
			"user",
			"User_Interfactor_Err: Failed UpdateUserPasswordByID",
			reqBodyInValid,
			"sdjbdklsdjk4566",
			token,
			nil,
			nil,
			http.StatusBadRequest,
			&apperrors.ControllerUpdateUserByIDRequestErr,
		},
		{
			"canUserVote == false",
			"user",
			"User_Interfactor_Err: check conditions",
			reqBody,
			userVoted.ID.String(),
			token,
			&userVoted,
			&userVoted,
			apperrors.InteractorCanUserVoteErr.HTTPCode,
			&apperrors.InteractorCanUserVoteErr,
		},
		{
			"vote success",
			"user",
			"success",
			reqBody,
			userId2.String(),
			token,
			&userVotes,
			&userVoted,
			http.StatusOK,
			nil,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, tc := range testTable {
		t.Run(tc.scenario, func(t *testing.T) {
			userRepoMock := mock.NewMockUserRepository(ctrl)
			userRepoMock.EXPECT().UpdateUserVotes(ctx, gomock.Any(), gomock.Any()).Return(tc.expectedError).AnyTimes()
			if tc.scenario == "canUserVote == false" {
				userRepoMock.EXPECT().GetUserByID(ctx, gomock.Any()).Return(tc.userVoted, tc.expectedError).AnyTimes()
			}

			if tc.expectedError == nil {
				userRepoMock.EXPECT().GetUserByID(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, uuid *uuid.UUID) (*models.User, error) {
					return tc.userVoted, tc.expectedError
				}).Times(1)

				userRepoMock.EXPECT().GetUserByID(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, uuid *uuid.UUID) (*models.User, error) {
					return tc.userVotes, tc.expectedError
				}).Times(1)

				userRepoMock.EXPECT().UpdateUserVotes(ctx, gomock.Any(), gomock.Any()).Return(tc.expectedError).AnyTimes()
			}
			uInteractor := interactor.NewUserInteractor(userRepoMock)
			config := config.Config{SecretKey: "secret"}
			uController := NewUserController(uInteractor, log, &config)
			e := echo.New()
			v := validator.NewValidator(log)
			e.Validator = v
			req := httptest.NewRequest(http.MethodPut, "/users/:voter_user_id/vote", bytes.NewBuffer(tc.inputUserReq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("voter_user_id")
			c.SetParamValues(tc.inputUserID)

			jwtConfig := middleware.JWTMiddlewareConfig{SecretKey: config.SecretKey}
			blacklist := middleware.NewBlacklist()
			JWTAuthFunc := middleware.JWTAuthentication(&jwtConfig, blacklist)
			handlerWithMiddleware := JWTAuthFunc(uController.VoteUser)
			err := handlerWithMiddleware(c)
			if err != nil {
				apperrors.IsAppError(err, tc.expectedError.(*apperrors.AppError))
				assert.Equal(t, tc.httpCode, err.(*echo.HTTPError).Code)
				return
			}

			assert.Equal(t, tc.httpCode, rec.Code)
			marshalledResponse, err := json.Marshal(tc.response)
			if assert.NoError(t, err) {
				assert.Equal(t, string(marshalledResponse), strings.TrimSuffix(rec.Body.String(), "\n"))
			}
		})
	}
}

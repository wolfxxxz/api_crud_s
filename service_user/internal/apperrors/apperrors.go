package apperrors

import (
	"fmt"
	"net/http"
)

type AppError struct {
	Message  string
	Code     string
	HTTPCode int
}

func NewAppError() *AppError {
	return &AppError{}
}

var (
	EnvConfigLoadError = AppError{
		Message:  "Failed to parse env file",
		Code:     envParse,
		HTTPCode: http.StatusInternalServerError,
	}
	EnvConfigParseError = AppError{
		Message:  "Failed to parse env file",
		Code:     envParse,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoInitFailedError = AppError{
		Message:  "Failed Init mongoDB",
		Code:     initMongo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoCreateUserFailedError = AppError{
		Message:  "Failed CreateUser",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoGetFailedError = AppError{
		Message:  "Failed GetUsersByPageAndPerPage",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoGetUserByIDErr = AppError{
		Message:  "Failed GetUserByID",
		Code:     userRepo,
		HTTPCode: http.StatusNotFound,
	}
	MongoGetUserByEmailErr = AppError{
		Message:  "Failed GetUserByEmail",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoUpdateUserByIDErr = AppError{
		Message:  "Failed UpdateUserByID",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoUpdateUserPasswordByIDErr = AppError{
		Message:  "Failed UpdateUserPasswordByID",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	MongoDropUserByIDErr = AppError{
		Message:  "Failed DropUserByID",
		Code:     userRepo,
		HTTPCode: http.StatusInternalServerError,
	}
	HashPasswordErr = AppError{
		Message:  "Hash Password Err",
		Code:     userInterfactor,
		HTTPCode: http.StatusInternalServerError,
	}
	MapCreateUserRequestToUserErr = AppError{
		Message:  "Create User Err",
		Code:     mapCreateUserRequestToUser,
		HTTPCode: http.StatusBadRequest,
	}
	ParsingStringToIntFailed = AppError{
		Message:  "Failed GetUsersByPageAndPerPage",
		Code:     userInterfactor,
		HTTPCode: http.StatusBadRequest,
	}
	CoverstionToUUIDFailed = AppError{
		Message:  "Failed GetUserByID",
		Code:     userInterfactor,
		HTTPCode: http.StatusBadRequest,
	}
	CoverstionToUUIDFailedUpdateUserByID = AppError{
		Message:  "Failed UpdateUserByID CoverstionToUUID",
		Code:     userInterfactor,
		HTTPCode: http.StatusBadRequest,
	}
	CoverstionToUUIDFailedUpdateUserPasswordByID = AppError{
		Message:  "Failed UpdateUserPasswordByID",
		Code:     userInterfactor,
		HTTPCode: http.StatusBadRequest,
	}
	CoverstionToUUIDFailedDropUserByID = AppError{
		Message:  "Failed DropUserByID",
		Code:     userInterfactor,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerCreateUserErr = AppError{
		Message:  "Failed CreateUser",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerGetUsersByPaginationError = AppError{
		Message:  "Failed GetUsersByPagination",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerGetUserByIDErr = AppError{
		Message:  "Failed GetUserByID",
		Code:     controller,
		HTTPCode: http.StatusForbidden,
	}
	ControllerUpdateUserByIDErr = AppError{
		Message:  "Failed UpdateUserByID",
		Code:     controller,
		HTTPCode: http.StatusForbidden,
	}
	InteractorUpdateUserPasswordByIDForbiddenErr = AppError{
		Message:  "Failed UpdateUserPasswordByID",
		Code:     userInterfactor,
		HTTPCode: http.StatusForbidden,
	}
	ControllerLoginErr = AppError{
		Message:  "Failed Login",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerLoginUnauthencitedUserErr = AppError{
		Message:  "Failed Login",
		Code:     controller,
		HTTPCode: http.StatusUnauthorized,
	}
	ControllerClaimJWTErr = AppError{
		Message:  "Failed claimJWTToken",
		Code:     controller,
		HTTPCode: http.StatusUnauthorized,
	}
	ControllerUpdateUserByIdErr = AppError{
		Message:  "Failed UpdateUserByID",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerUpdateUserByIDRequestErr = AppError{
		Message:  "Failed UpdateUserByID",
		Code:     controller,
		HTTPCode: http.StatusConflict,
	}
	ControllerUpdateUserPasswordByIDErr = AppError{
		Message:  "Failed UpdateUserPasswordByID",
		Code:     controller,
		HTTPCode: http.StatusUnauthorized,
	}
	ControllerDropUserByIDErr = AppError{
		Message:  "Failed DropUserByID",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerDropUserByIDErrUnAuth = AppError{
		Message:  "Failed DropUserByID",
		Code:     controller,
		HTTPCode: http.StatusUnauthorized,
	}
	ValidateErr = AppError{
		Message:  "Validate Err",
		Code:     validate,
		HTTPCode: http.StatusBadRequest,
	}
	InitMiddlewareErr = AppError{
		Message:  "Innit Middleware secret key",
		Code:     initMiddleware,
		HTTPCode: http.StatusBadRequest,
	}
	JWTMiddleware = AppError{
		Message:  "JWT Middleware",
		Code:     jWTMiddleware,
		HTTPCode: http.StatusUnauthorized,
	}
	InteractorCanUserVoteErr = AppError{
		Message:  "check conditions",
		Code:     userInterfactor,
		HTTPCode: http.StatusUnauthorized,
	}
	InteractorVoteUserErr = AppError{
		Message:  "Failed VoteUser",
		Code:     userInterfactor,
		HTTPCode: http.StatusUnauthorized,
	}
	ControllerUpdateUserPasswordByIdErr = AppError{
		Message:  "Failed UpdateUserPasswordById",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerGetUserByIdErr = AppError{
		Message:  "Failed GetUserById",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerVoteUserBindErr = AppError{
		Message:  "Failed VoteUserBind",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	ControllerVoteUserErr = AppError{
		Message:  "Failed VoteUserBind",
		Code:     controller,
		HTTPCode: http.StatusBadRequest,
	}
	MongoUpdateUserVotesErr = AppError{
		Message:  "Failed VoteUserBind",
		Code:     userRepo,
		HTTPCode: http.StatusBadRequest,
	}
	MongoGetTwoUsersByIDErr = AppError{
		Message:  "Failed GetTwoUsers",
		Code:     userRepo,
		HTTPCode: http.StatusBadRequest,
	}
)

func (appError *AppError) HttpCode() int {
	return appError.HTTPCode
}

func (appError *AppError) Error() string {
	return appError.Code + ": " + appError.Message
}

func (appError *AppError) AppendMessage(anyErrs ...interface{}) *AppError {
	return &AppError{
		Message:  fmt.Sprintf("%v : %v", appError.Message, anyErrs),
		Code:     appError.Code,
		HTTPCode: appError.HTTPCode,
	}
}

func IsAppError(err1 error, err2 *AppError) bool {
	err, ok := err1.(*AppError)
	if !ok {
		return false
	}

	return err.Code == err2.Code
}

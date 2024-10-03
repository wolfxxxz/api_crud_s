package validator

import (
	"net/http"
	"service_user/internal/apperrors"

	"github.com/go-playground/validator"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

type CustomValidator struct {
	validator *validator.Validate
	log       *logrus.Logger
}

func NewValidator(log *logrus.Logger) *CustomValidator {
	return &CustomValidator{validator: validator.New(), log: log}
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		appErr := apperrors.ValidateErr.AppendMessage(err)
		cv.log.Error(appErr)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return nil
}

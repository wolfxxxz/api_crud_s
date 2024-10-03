package main

import (
	"context"
	"service_user/internal/apperrors"
	"service_user/internal/config"
	"service_user/internal/domain/validator"
	"service_user/internal/infrastructure/datastore"
	"service_user/internal/infrastructure/router"
	"service_user/internal/log"
	"service_user/internal/registry"

	"github.com/labstack/echo"
)

func main() {
	logger, err := log.NewLogAndSetLevel("info")
	if err != nil {
		logger.Debug(err)
	}

	conf := config.NewConfig()
	err = conf.ParseConfig("config/.env", logger)
	if err != nil {
		logger.Fatal(apperrors.EnvConfigLoadError.AppendMessage(err))
	}

	if err = log.SetLevel(logger, conf.LogLevel); err != nil {
		logger.Debug(err)
	}

	ctx := context.Background()

	mongoDB, err := datastore.InintMongoDB(ctx, conf, logger)
	if err != nil {
		logger.Error(err)
	}

	r := registry.NewRegistry(mongoDB, logger, conf)
	e := echo.New()
	e.Validator = validator.NewValidator(logger)
	e = router.NewRouter(e, r.NewAppController(), conf.SecretKey)
	logger.Infof("Server listen at http://%s:%s", conf.Host, conf.Port)
	if err := e.Start(":" + conf.Port); err != nil {
		logger.Fatalln(err)
	}
}

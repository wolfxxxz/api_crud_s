package config

import (
	"fmt"
	"service_user/internal/apperrors"

	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Port                   string `env:"PORT"`
	LogLevel               string `env:"LOGGER_LEVEL"`
	MongoHost              string `env:"MONGO_URL"`
	MongoPort              string `env:"MONGO_PORT"`
	UserName               string `env:"USER_NAME"`
	DBName                 string `env:"DB_NAME"`
	Password               string `env:"PASSWORD"`
	TimeoutMongoQuery      string `env:"TIMEOUT_MONGO_QUERY"`
	Host                   string `env:"HOST"`
	ExpirationJWTInSeconds string `env:"EXPIRATION_JWT_IN_SECONDS"`
	SecretKey              string `env:"SECRET_KEY"`
}

func NewConfig() *Config {
	return &Config{}
}

func (v *Config) ParseConfig(path string, log *logrus.Logger) error {
	err := godotenv.Load(path)
	if err != nil {
		errMsg := fmt.Sprintf(" %s", err.Error())
		log.Info("gotoenv could not find .env", errMsg)
		return apperrors.EnvConfigParseError.AppendMessage(errMsg)
	}

	if err := env.Parse(v); err != nil {
		errMsg := fmt.Sprintf("%+v\n", err)
		return apperrors.EnvConfigParseError.AppendMessage(errMsg)
	}

	log.Info("Config has been parsed, succesfully!!!")
	return nil
}

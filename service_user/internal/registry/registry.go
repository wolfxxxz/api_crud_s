package registry

import (
	"service_user/internal/config"
	"service_user/internal/interface/controller"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

type registry struct {
	log    *logrus.Logger
	db     *mongo.Database
	config *config.Config
}

type Registry interface {
	NewAppController() controller.AppController
}

func NewRegistry(db *mongo.Database, log *logrus.Logger, config *config.Config) Registry {
	return &registry{db: db, log: log, config: config}
}

func (r *registry) NewAppController() controller.AppController {
	return controller.AppController{
		UserController: r.NewUserController(),
	}
}

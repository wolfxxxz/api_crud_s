package repository

import (
	"context"
	"service_user/internal/domain/models"

	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, req *models.User) (string, error)
	GetUsersByPageAndPerPage(ctx context.Context, page, perPage int) ([]*models.User, error)
	GetUserByID(ctx context.Context, userUUID *uuid.UUID) (*models.User, error)

	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	UpdateUserByID(ctx context.Context, user *models.User) (string, error)
	UpdateUserPasswordByID(ctx context.Context, req *models.User) (string, error)
	DropUserByID(ctx context.Context, userUUID *uuid.UUID) error

	UpdateUserVotes(ctx context.Context, user *models.User, votedUser *models.User) error
	UpdateUserVote(ctx context.Context, votedUser *models.User, voterUser *models.User, existingVote *models.Vote) error
}

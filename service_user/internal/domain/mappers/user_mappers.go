package mappers

import (
	"service_user/internal/apperrors"
	"service_user/internal/domain/models"
	"service_user/internal/domain/requests"
	"service_user/internal/domain/responses"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func MapCreateUserRequestToUser(createUserRequest *requests.CreateUserRequest) (*models.User, error) {
	if createUserRequest.FirstName == "" {
		return nil, &apperrors.MapCreateUserRequestToUserErr
	}

	user := MapToUser(createUserRequest.Email, createUserRequest.UserName, createUserRequest.FirstName,
		createUserRequest.LastName, createUserRequest.Password, createUserRequest.Role)
	return user, nil
}

func MapUsersToGetUsersByPaginationResponse(users []*models.User, page, perPage string) *responses.GetUsersByPaginationResponse {
	totalUsers := len(users)
	var usersResponse []*responses.GetUsersByIdResponse
	for _, user := range users {
		var userResponse responses.GetUsersByIdResponse
		userResponse.Email = user.Email
		userResponse.FirstName = user.FirstName
		userResponse.ID = user.ID
		userResponse.LastName = user.LastName
		userResponse.UserName = user.UserName
		userResponse.Rating = user.Rating()
		usersResponse = append(usersResponse, &userResponse)
	}

	return &responses.GetUsersByPaginationResponse{Users: usersResponse, Page: page, PerPage: perPage, TotalUsers: totalUsers}
}

func MapUserToGetUserByIdResponse(user *models.User) *responses.GetUsersByIdResponse {
	rating := user.Rating()
	return &responses.GetUsersByIdResponse{ID: user.ID, Email: user.Email, UserName: user.UserName,
		LastName: user.LastName, FirstName: user.FirstName, Rating: rating}
}

func MapUpdateUserRequestToUser(requestUser *requests.UpdateUserRequest) (*models.User, error) {
	now := primitive.NewDateTimeFromTime(time.Now())
	userUUID, err := uuid.Parse(requestUser.ID)
	if err != nil {
		return nil, &apperrors.CoverstionToUUIDFailedUpdateUserByID
	}

	return &models.User{ID: &userUUID, Email: requestUser.Email, UserName: requestUser.UserName,
		FirstName: requestUser.FirstName, LastName: requestUser.LastName, Updated: &now}, nil
}

func MapUpdateUserPasswordRequestToUser(updateUserPasswordRequest *requests.UpdateUserPasswordRequest) (*models.User, error) {
	now := primitive.NewDateTimeFromTime(time.Now())
	userUUID, err := uuid.Parse(updateUserPasswordRequest.ID)
	if err != nil {
		return nil, &apperrors.CoverstionToUUIDFailedUpdateUserByID
	}

	return &models.User{ID: &userUUID, Password: updateUserPasswordRequest.NewPassword, Updated: &now}, nil
}

func MapTokenToLoginResponse(token string, expiresAt string) *responses.LoginResponse {
	return &responses.LoginResponse{Token: token, ExpiresIn: expiresAt, TokenType: "jwt", RefreshToken: "it'll be soon"}
}

func MapToUser(email, userName, firstName, lastName, password, role string) *models.User {
	var votes []*models.Vote
	id := uuid.New()
	now := primitive.NewDateTimeFromTime(time.Now())
	return &models.User{ID: &id, Email: email, UserName: userName,
		FirstName: firstName, LastName: lastName, Role: role,
		Password: password, Created: &now, Votes: votes}
}

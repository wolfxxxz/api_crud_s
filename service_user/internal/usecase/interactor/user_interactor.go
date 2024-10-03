package interactor

import (
	"context"
	"fmt"
	"service_user/internal/apperrors"
	"service_user/internal/domain/mappers"
	"service_user/internal/domain/models"
	"service_user/internal/domain/requests"
	"service_user/internal/domain/responses"
	"service_user/internal/usecase/repository"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type userInteractor struct {
	UserRepository repository.UserRepository
}

type UserInteractor interface {
	CreateUser(ctx context.Context, createUserRequest *requests.CreateUserRequest) (string, error)
	GetUsersByPageAndPerPage(ctx context.Context, page, perPage string) (*responses.GetUsersByPaginationResponse, error)
	GetUserByID(ctx context.Context, id string) (*responses.GetUsersByIdResponse, error)

	SignInUserWithJWT(ctx context.Context, postUserRequest *requests.LoginRequest, sekretKey string, expiresAt string) (*responses.LoginResponse, error)

	UpdateUserByID(ctx context.Context, updateUserRequest *requests.UpdateUserRequest, authID string, role string) (string, error)
	UpdateUserPasswordByID(ctx context.Context, updateUserPasswordRequest *requests.UpdateUserPasswordRequest, authID string) (string, error)
	DropUserByID(ctx context.Context, id string, authID string, role string) error

	VoteUser(ctx context.Context, votedUserID string, voterUserId string, voteRequest *requests.VoteRequest) error
}

func NewUserInteractor(r repository.UserRepository) UserInteractor {
	return &userInteractor{r}
}

func (us *userInteractor) VoteUser(ctx context.Context,
	votedUserId string, voterUserId string, voteRequest *requests.VoteRequest) error {
	votedUserUUID, err := uuid.Parse(votedUserId)
	if err != nil {
		msg := fmt.Sprintf("VoteUser Cannot convert UserID to UUID. Err: %v", err)
		return apperrors.CoverstionToUUIDFailed.AppendMessage(msg)
	}

	voterUserUUID, err := uuid.Parse(voterUserId)
	if err != nil {
		msg := fmt.Sprintf("VoteUser Cannot convert UserID to UUID. Err: %v", err)
		return apperrors.CoverstionToUUIDFailed.AppendMessage(msg)
	}

	votedUser, err := us.UserRepository.GetUserByID(ctx, &votedUserUUID)
	if err != nil {
		return err
	}

	voterUser, err := us.UserRepository.GetUserByID(ctx, &voterUserUUID)
	if err != nil {
		return err
	}

	voteValue, err := strconv.Atoi(voteRequest.VoteValue)
	if err != nil {
		appError := apperrors.ParsingStringToIntFailed.AppendMessage("VoteUser Error")
		return appError
	}

	existingVote, ok := canUserVote(votedUser, voterUser, voteValue)
	if !ok {
		appErr := apperrors.InteractorCanUserVoteErr.AppendMessage("some rules were not followed")
		return appErr
	}

	if existingVote != nil {
		existingVote.Vote = voteValue
		now := primitive.NewDateTimeFromTime(time.Now())
		existingVote.VotedAt = &now
		votedUser.VotedAt = &now
		return us.UserRepository.UpdateUserVote(ctx, votedUser, voterUser, existingVote)
	}

	now := primitive.NewDateTimeFromTime(time.Now())
	vote := &models.Vote{
		VotedUserID: votedUser.ID,
		Vote:        voteValue,
		VotedAt:     &now,
	}

	votedUser.VotedAt = &now
	voterUser.Votes = append(voterUser.Votes, vote)
	return us.UserRepository.UpdateUserVotes(ctx, votedUser, voterUser)
}

func canUserVote(votedUser *models.User, voterUser *models.User, voteValue int) (*models.Vote, bool) {
	if voteValue != 1 && voteValue != -1 {
		log.Error("VOTE:", voteValue)
		return nil, false
	}

	log.Info("\n", votedUser.ID.String(), "\n", voterUser.ID.String())
	if votedUser.ID.String() == voterUser.ID.String() {
		log.Error("ID:", votedUser.ID.String(), "||", voterUser.ID.String())
		return nil, false
	}

	if votedUser.VotedAt != nil && votedUser.VotedAt.Time().Add(60*time.Minute).After(time.Now()) {
		log.Error("TIME LAST VOTE", votedUser.VotedAt)
		return nil, false
	}

	for _, existingVote := range voterUser.Votes {
		if existingVote.VotedUserID.String() == votedUser.ID.String() {
			if existingVote.Vote == voteValue {
				log.Error("THE USER VOTED THE SAME LAST TIME ", existingVote.Vote, "==", voteValue, "I=", voteValue)
				return nil, false
			}

			log.Info("THE USER WANTS TO UPDATE HIS VOTE")
			return existingVote, true
		}
	}

	return nil, true
}

func (us *userInteractor) CreateUser(ctx context.Context, createUserRequest *requests.CreateUserRequest) (string, error) {
	user, err := mappers.MapCreateUserRequestToUser(createUserRequest)
	if err != nil {
		return "", err
	}

	hashPass, err := hashPassword(user.Password)
	if err != nil {
		return "", err
	}

	user.Password = hashPass
	return us.UserRepository.CreateUser(ctx, user)
}

func (us *userInteractor) GetUsersByPageAndPerPage(ctx context.Context, pageIn, perPageIn string) (*responses.GetUsersByPaginationResponse, error) {
	page, err := strconv.Atoi(pageIn)
	if err != nil {
		msg := fmt.Sprintf("Cannot parse page to int. Err: %v", err)
		return nil, apperrors.ParsingStringToIntFailed.AppendMessage(msg)
	}

	perPage, err := strconv.Atoi(perPageIn)
	if err != nil {
		msg := fmt.Sprintf("Cannot parse per page to int. Err: %v", err)
		return nil, apperrors.ParsingStringToIntFailed.AppendMessage(msg)
	}

	users, err := us.UserRepository.GetUsersByPageAndPerPage(ctx, page, perPage)
	if err != nil {
		return nil, err
	}

	respUsers := mappers.MapUsersToGetUsersByPaginationResponse(users, pageIn, perPageIn)
	return respUsers, nil
}

func (us *userInteractor) GetUserByID(ctx context.Context, id string) (*responses.GetUsersByIdResponse, error) {
	userUUID, err := uuid.Parse(id)
	if err != nil {
		msg := fmt.Sprintf("Cannot convert UserID to UUID. Err: %v", err)
		return nil, apperrors.CoverstionToUUIDFailed.AppendMessage(msg)
	}

	user, err := us.UserRepository.GetUserByID(ctx, &userUUID)
	if err != nil {
		return nil, err
	}

	log.Info("RATING", user)

	getUsersByIdResp := mappers.MapUserToGetUserByIdResponse(user)
	return getUsersByIdResp, nil
}

func (us *userInteractor) SignInUserWithJWT(ctx context.Context, postUserRequest *requests.LoginRequest, sekretKey string, expiresAt string) (*responses.LoginResponse, error) {
	user, err := us.UserRepository.GetUserByEmail(ctx, postUserRequest.Email)
	if err != nil {
		return nil, err
	}

	log.Info(postUserRequest.Password, user.Password)

	if !checkPasswordHash(postUserRequest.Password, user.Password) {
		log.Infof("This is an ERROR : %v", err)
		return nil, err
	}

	token, err := claimJWTToken(user.Role, user.ID.String(), expiresAt, []byte(sekretKey))
	if err != nil {
		return nil, err
	}

	return mappers.MapTokenToLoginResponse(token, expiresAt), nil
}

func (us *userInteractor) UpdateUserByID(ctx context.Context, updateUserRequest *requests.UpdateUserRequest, authID string, role string) (string, error) {
	if ok := canManageUser(authID, role, updateUserRequest.ID); !ok {
		appErr := apperrors.ControllerUpdateUserByIDErr.AppendMessage("unauthorized")
		return "", appErr
	}

	user, err := mappers.MapUpdateUserRequestToUser(updateUserRequest)
	if err != nil {
		return "", err
	}

	log.Infof("USER %+v", user)
	return us.UserRepository.UpdateUserByID(ctx, user)
}

func (us *userInteractor) UpdateUserPasswordByID(ctx context.Context, updateUserPasswordRequest *requests.UpdateUserPasswordRequest, authID string) (string, error) {
	if ok := canManageUserChangeHisPassword(authID, updateUserPasswordRequest.ID); !ok {
		appErr := apperrors.InteractorUpdateUserPasswordByIDForbiddenErr.AppendMessage("unauthorized")
		return "", appErr
	}

	user, err := mappers.MapUpdateUserPasswordRequestToUser(updateUserPasswordRequest)
	if err != nil {
		return "", err
	}

	log.Infof("USER %+v", user)

	hashPass, err := hashPassword(user.Password)
	if err != nil {
		return "", err
	}

	user.Password = hashPass
	return us.UserRepository.UpdateUserPasswordByID(ctx, user)
}

func (us *userInteractor) DropUserByID(ctx context.Context, id string, authID string, role string) error {
	if ok := canManageUser(authID, role, id); !ok {
		appErr := apperrors.ControllerDropUserByIDErr.AppendMessage("not enough rigths, role is wrong")
		return appErr
	}

	userUUID, err := uuid.Parse(id)
	if err != nil {
		return apperrors.CoverstionToUUIDFailedDropUserByID.AppendMessage(err)
	}

	return us.UserRepository.DropUserByID(ctx, &userUUID)
}

func claimJWTToken(role string, id string, expiresAt string, sekretKey []byte) (string, error) {
	expiresAtNum, err := strconv.Atoi(expiresAt)
	if err != nil {
		appErr := apperrors.InitMiddlewareErr.AppendMessage(err)
		log.Error(appErr)
		return "", appErr
	}

	t := time.Duration(expiresAtNum) * time.Second
	claims := jwt.MapClaims{
		"role": role,
		"id":   id,
		"exp":  time.Now().Add(t).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(sekretKey)
	if err != nil {
		return "", &apperrors.ControllerClaimJWTErr
	}

	return signedToken, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", apperrors.HashPasswordErr.AppendMessage(err)
	}

	return string(bytes), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func canManageUser(authID, role, userRequestID string) bool {
	if role == "admin" {
		return true
	}

	if authID == userRequestID {
		return true
	}

	return false
}

func canManageUserChangeHisPassword(authID, userRequestID string) bool {
	return authID == userRequestID
}

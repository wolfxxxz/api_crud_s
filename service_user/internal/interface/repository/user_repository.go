package repository

import (
	"context"
	"service_user/internal/apperrors"
	"service_user/internal/domain/models"
	"service_user/internal/usecase/repository"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson"
)

const userCollection = "users"

type userRepository struct {
	log        *logrus.Logger
	collection *mongo.Collection
}

func NewUserRepository(db *mongo.Database, log *logrus.Logger) repository.UserRepository {
	return &userRepository{collection: db.Collection(userCollection), log: log}
}

func (ur *userRepository) UpdateUserVotes(ctx context.Context, votedUser *models.User, voterUser *models.User) error {
	session, err := ur.collection.Database().Client().StartSession()
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	defer session.EndSession(ctx)

	err = session.StartTransaction()
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	err = ur.updateVotedAtByUserId(ctx, session, votedUser.ID, votedUser.VotedAt)
	if err != nil {
		session.AbortTransaction(ctx)
		return err
	}

	err = ur.updateVotesByUserID(ctx, session, voterUser.ID, voterUser.Votes)
	if err != nil {
		session.AbortTransaction(ctx)
		return err
	}

	err = session.CommitTransaction(ctx)
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	return nil
}

func (ur *userRepository) UpdateUserVote(ctx context.Context, votedUser *models.User, voterUser *models.User, existingVote *models.Vote) error {
	session, err := ur.collection.Database().Client().StartSession()
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	defer session.EndSession(ctx)

	err = session.StartTransaction()
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	err = ur.updateVotedAtByUserId(ctx, session, votedUser.ID, votedUser.VotedAt)
	if err != nil {
		session.AbortTransaction(ctx)
		return err
	}

	err = ur.updateVoteByUserID(ctx, session, voterUser.ID, existingVote.VotedUserID, existingVote.Vote)
	if err != nil {
		session.AbortTransaction(ctx)
		return err
	}

	err = session.CommitTransaction(ctx)
	if err != nil {
		return apperrors.MongoUpdateUserVotesErr.AppendMessage(err)
	}

	return nil
}

func (ur *userRepository) updateVoteByUserID(ctx context.Context, session mongo.Session, voterUserID *uuid.UUID, votedUserID *uuid.UUID, voteValue int) error {
	filter := bson.M{"_id": voterUserID,
		"votes.voted_id": votedUserID,
	}

	update := bson.M{
		"$set": bson.M{
			"votes.$.vote": voteValue,
		},
	}

	res, err := ur.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage(err)
	}

	if res.MatchedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("not found %v", voterUserID)
	}

	if res.ModifiedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("nothing is modified %v", voterUserID)
	}

	ur.log.Infof(" result  UpdateUserById %+v", res)
	return nil
}

func (ur *userRepository) updateVotedAtByUserId(ctx context.Context, session mongo.Session,
	id *uuid.UUID, votedAt *primitive.DateTime) error {
	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"voted_at": votedAt,
		},
	}

	res, err := ur.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage(err)
	}

	if res.MatchedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("not found %v", id)
	}

	if res.ModifiedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("nothing is modified %v", id)
	}

	ur.log.Infof(" result  UpdateUserById %+v", res)
	return nil
}

func (ur *userRepository) updateVotesByUserID(ctx context.Context, session mongo.Session, id *uuid.UUID, votes []*models.Vote) error {
	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"votes": votes,
		},
	}

	res, err := ur.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage(err)
	}

	if res.MatchedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("not found %v", id)
	}

	if res.ModifiedCount != 1 {
		return apperrors.MongoUpdateUserByIDErr.AppendMessage("nothing is modified %v", id)
	}

	ur.log.Infof(" result  UpdateUserById %+v", res)
	return nil
}

func (ur *userRepository) CreateUser(ctx context.Context, u *models.User) (string, error) {
	res, err := ur.collection.InsertOne(ctx, u)
	if err != nil {
		return "", apperrors.MongoCreateUserFailedError.AppendMessage(err)
	}

	objectId := res.InsertedID.(primitive.Binary).Data
	objectUUID, err := uuid.FromBytes(objectId)
	if err != nil {
		return "", apperrors.MongoCreateUserFailedError.AppendMessage(err)
	}

	ur.log.Info("ID result SaveUser ", objectUUID)
	return objectUUID.String(), nil
}

func (ur *userRepository) GetUsersByPageAndPerPage(ctx context.Context, page, perPage int) ([]*models.User, error) {
	offset := (page - 1) * perPage
	filter := bson.D{}
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: 1}}).
		SetSkip(int64(offset)).
		SetLimit(int64(perPage))

	cursor, err := ur.collection.Find(ctx, filter, opts)
	if err != nil {
		ur.log.Error(err)
		return nil, apperrors.MongoGetFailedError.AppendMessage(err)
	}

	defer cursor.Close(ctx)
	return decodeUsers(ctx, cursor)
}

func (ur *userRepository) GetUserByID(ctx context.Context, userUUID *uuid.UUID) (*models.User, error) {
	filter := bson.M{"_id": userUUID}
	res := ur.collection.FindOne(ctx, filter)
	if res.Err() != nil {
		ur.log.Errorf("Cannot find user by _id. Err: %+v", res.Err())
		return nil, apperrors.MongoGetUserByIDErr.AppendMessage(res.Err())
	}

	user := models.User{}
	err := res.Decode(&user)
	if err != nil {
		return nil, apperrors.MongoGetUserByIDErr.AppendMessage(res.Err())
	}

	ur.log.Info("The user has been finded, successfully.")
	return &user, nil
}

func (ur *userRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	filter := bson.M{"user_email": email}
	res := ur.collection.FindOne(ctx, filter)
	if res.Err() != nil {
		ur.log.Errorf("Cannot find user by email. Err: %+v", res.Err())
		return nil, apperrors.MongoGetUserByEmailErr.AppendMessage(res.Err())
	}

	user := models.User{}
	err := res.Decode(&user)
	if err != nil {
		return nil, apperrors.MongoGetUserByEmailErr.AppendMessage(err)
	}

	ur.log.Info("The user has been finded, successfully.")
	return &user, nil
}

func (ur *userRepository) UpdateUserByID(ctx context.Context, user *models.User) (string, error) {
	filter := bson.M{"_id": user.ID}
	ur.log.Infof("USER %v", user)
	update := bson.M{
		"$set": bson.M{
			"user_email": user.Email,
			"first_name": user.FirstName,
			"user_name":  user.UserName,
			"last_name":  user.LastName,
			"updated_at": user.Updated,
		},
	}

	res, err := ur.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return "", apperrors.MongoUpdateUserByIDErr.AppendMessage(err)
	}

	if res.MatchedCount != 1 {
		return "", apperrors.MongoUpdateUserByIDErr.AppendMessage("not found %v", user.ID)
	}

	if res.ModifiedCount != 1 {
		return "", apperrors.MongoUpdateUserByIDErr.AppendMessage("nothing is modified %v", user.ID)
	}

	ur.log.Infof(" result  UpdateUserById %+v", res)
	return user.Email, nil
}

func (ur *userRepository) UpdateUserPasswordByID(ctx context.Context, user *models.User) (string, error) {
	filter := bson.M{"_id": user.ID}
	ur.log.Infof("USER %v", user)
	update := bson.M{
		"$set": bson.M{
			"password":   user.Password,
			"updated_at": user.Updated,
		},
	}

	res, err := ur.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return "", apperrors.MongoUpdateUserPasswordByIDErr.AppendMessage(err)
	}

	if res.MatchedCount != 1 {
		return "", apperrors.MongoUpdateUserPasswordByIDErr.AppendMessage("not found %v", user.ID)
	}

	if res.ModifiedCount != 1 {
		return "", apperrors.MongoUpdateUserPasswordByIDErr.AppendMessage("nothing is modified %v", user.ID)
	}

	ur.log.Infof("result UpdateUserByID %+v", res)
	return "updated", nil
}

func (ur *userRepository) DropUserByID(ctx context.Context, userUUID *uuid.UUID) error {
	filter := bson.M{"_id": userUUID}
	res, err := ur.collection.DeleteOne(ctx, filter)
	if err != nil {
		appErr := apperrors.MongoDropUserByIDErr.AppendMessage(err)
		ur.log.Errorf("Cannot find user by _id. Err: %+v", err)
		return appErr
	}

	if res.DeletedCount != 1 {
		return apperrors.MongoDropUserByIDErr.AppendMessage("nothing was deleted %v", userUUID)
	}

	ur.log.Info("The user has been deleted, successfully.")
	return nil
}

func decodeUsers(ctx context.Context, cursor *mongo.Cursor) ([]*models.User, error) {
	defer cursor.Close(ctx)
	var users []*models.User
	for cursor.Next(ctx) {
		var user models.User
		err := cursor.Decode(&user)
		if err != nil {
			return nil, apperrors.MongoGetFailedError.AppendMessage(err)
		}

		users = append(users, &user)
	}

	if err := cursor.Err(); err != nil {
		return nil, apperrors.MongoGetFailedError.AppendMessage(err)
	}

	return users, nil
}

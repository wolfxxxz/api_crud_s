package models

import (
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        *uuid.UUID          `bson:"_id"`
	Email     string              `bson:"user_email"`
	UserName  string              `bson:"user_name"`
	FirstName string              `bson:"first_name"`
	LastName  string              `bson:"last_name"`
	Password  string              `bson:"password"`
	Role      string              `bson:"role"`
	Created   *primitive.DateTime `bson:"created_at"`
	Updated   *primitive.DateTime `bson:"updated_at"`
	Deleted   *primitive.DateTime `bson:"deleted_at"`
	VotedAt   *primitive.DateTime `bson:"voted_at"`
	Votes     []*Vote             `bson:"votes"`
}

type Vote struct {
	VotedUserID *uuid.UUID          `bson:"voted_id"`
	Vote        int                 `bson:"vote"`
	VotedAt     *primitive.DateTime `bson:"voted_at"`
}

func (person *User) Update() bool {
	now := primitive.NewDateTimeFromTime(time.Now())
	person.Updated = &now
	return true
}

func (user *User) Rating() int {
	rating := 0
	if user.Votes != nil {
		for _, v := range user.Votes {
			rating += v.Vote
		}
	}

	return rating
}

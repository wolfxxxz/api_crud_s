package responses

import (
	"github.com/google/uuid"
)

type GetUsersByPaginationResponse struct {
	Users      []*GetUsersByIdResponse `json:"users"`
	Page       string                  `json:"page"`
	PerPage    string                  `json:"per_page"`
	TotalUsers int                     `json:"total_users"`
}

type GetUsersByIdResponse struct {
	ID        *uuid.UUID `json:"id"`
	Email     string     `json:"email"`
	UserName  string     `json:"user_name"`
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Rating    int        `json:"rating"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type VotedUserResponse struct {
	VotesValue int `json:"votes_value"`
	Votes      int `json:"votes"`
}

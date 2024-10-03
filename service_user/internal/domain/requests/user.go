package requests

type CreateUserRequest struct {
	Email     string `json:"email" validate:"required,email"`
	UserName  string `json:"user_name" validate:"required"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Password  string `json:"password" validate:"required"`
	Role      string `json:"role" validate:"required,oneof=user moderator admin"`
}

type UpdateUserRequest struct {
	ID        string
	Email     string `json:"email" validate:"required"`
	UserName  string `json:"user_name" validate:"required"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

type UpdateUserPasswordRequest struct {
	ID               string
	ExistingPassword string `json:"existing_password" validate:"required"`
	NewPassword      string `json:"password" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type DeleteUserRequest struct {
	ID string `json:"user_id" validate:"required"`
}

type VoteRequest struct {
	VoteValue string `json:"vote_value" validate:"required"`
}

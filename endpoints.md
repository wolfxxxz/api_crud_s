# 1.Create user profile
    URL: /users
    method: POST
        Request Body:
          {
              "email": "user_email",
              "user_name": "user_alias",
              "first_name": "John",
              "last_name": "Doe",
              "password": "secure_password",
              "role": "user or moderator or admin",
          }
        Response:
          201 Created
              Response body:
              {
              "JWT": 1lkjfsw8293ur2elkwjelw
              }
          400 Bad Request
              Response body:
              {"error": "Incorrect field"}
          409 Conflict
              Response body:
              {"error": "Invalid request body"}
# 2.Read user profile 
    URL: /users/:user_id
    method: GET
        Path Parameters:
          user_id
        Authorization:
          JWT
        Response:
          200 OK
              Response Body:
              {
              "id": 1,
              "email": "user_email",
              "user_name": "user_alias",
              "first_name": "John",
              "last_name": "Doe",
              "role": "user or moderator or admin",
              }
          400 Bad Request
              Response body:
              {"error": "Incorrect field"}
          404 Not Found
              Response body:
              {"error": "User not found"}
          500 InternalServerError
              Response body:
              {"error": "Internal server error"}
# 3.Update user profile
    URL: /users/update/:user_id
    method: PUT
        Path Parameters:
          user_id
        Authorization:
          JWT
        Request Body:
              {
              "email": "user_email",
              "user_name": "user_alias",
              "first_name": "John",
              "last_name": "Doe",
              }
        Response:
          200 OK +
              Response Body:
              {
              "id": 1
              }
          401 Unauthorized
              Response Body:
              {"error": "Unauthorized: User authentication failed"}
          400 Bad Request 
              Response body:
              {"error": "Incorrect field"}
          404 Not Found
              Response body:
              {"error": "User not found"}
          409 Conflict +
              Response body:
              {"error": "Invalid request body"}
          500 InternalServerError
              Response body:
              {"error": "Internal server error"}
# 4.Update user password
    URL: /users/update_password/:user_id
    method: PUT
        Path Parameters:
          user_id
        Authorization:
          JWT
        Request Body:
              { 
                "existing_password": "old_password",
                "password": "new_secure_password"
              }
        Response:
          200 OK
              Response Body:
              {"message": "Password updated successfully"}
          400 Bad request
              Response Body:
              {"error": "Invalid request: Old password is incorrect"}
          401 Unauthorized
              Response Body:
              {"error": "Unauthorized: User authentication failed"}
          409 Conflict
              Response body:
              {"error": "Invalid request body"}
          500 InternalServerError
              Response body:
              {"error": "Internal server error"}
# 5.List of user profiles
    URL: /users/pagination?page=1&per_page=10
    method: GET
        Query Parameters:
          page
          per_page
        Response:
          200 OK
              Response Body:
              {
                  "users": [
                      {
                          "id": 1,
                          "email": "user_email",
                          "user_name": "user_alias",
                          "first_name": "John",
                          "last_name": "Doe",
                      },
                      {
                          "id": 2,
                          "email": "another_user_email",
                          "user_name": "user_alias",
                          "first_name": "Alice",
                          "last_name": "Smith",
                      }
                  ],
                  "page": 1,
                  "per_page": 10,
                  "total_users": 2
              }
          400 Bad request
              Response Body:
              {"error": "wrong parameters page, per_page"}
          500 InternalServerError
              Response body:
              {"error": "Internal server error"}
# 6.User Login
    URL: /login
    method: POST
        Request Body:
              {
                "email": "user_email",
                "password": "secure_password"
              }
        Response:
          200 OK
              Response Body:
              {
                "access_token": "access_token",
                "expires_at": "2023-01-01T12:00:00Z",
              }
          401 Unauthorized
              Response Body:
              {"error": "Invalid credentials"}
          400 Bad Request
              Response body:
              {"error": "Incorrect field"}
          409 Conflict 
              Response body:
              {"error": "Invalid request body"}
# 7.User Logout
    URL: /logout
    method: POST
        Authorization:
            Basic Auth
        Response:
          200 OK
              Response Body:
              {"message": "Logout successful"}
          401 Unauthorized
              Response Body:
              {"error": "Invalid or expired token"}
# 8.Check token
    URL: /protected
    method: GET
        Authorization:
            Basic Auth
        Response:
          200 OK
              Response Body:
              {"message": "Token is valid"}
          401 Unauthorized
              Response Body:
              {"error": "Invalid or expired token"}
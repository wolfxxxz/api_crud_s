# User Management & Authentication API
    This API provides standard CRUD operations for user management and enables users to vote for other users. It implements a clean architecture design with echo router and uses MongoDB for data storage.

# Key Features:
    User Authentication: Provides secure user authentication with JWT tokens for session management.
    User Voting System: Users can vote for other users, creating an interactive user ranking or preference feature.
    CRUD Operations: Standardized Create, Read, Update, and Delete operations for managing user data.
    Token Expiration Management: Issues temporary tokens that expire after a specific period, ensuring security.
    MongoDB Integration: Efficient data storage and management using MongoDB.
    Clean Architecture: Separation of concerns with a clean, maintainable architecture design.
    Input Validation: Ensures data integrity through structured validation using validator.
    Error Handling and Logging: Implements robust error handling with structured logging using logrus.
    Scalable Design: Can easily scale and be extended with additional features as needed.
    API Documentation: Integrated documentation for ease of use and clarity for external developers.
    Docker Compose for deploying the project in the cloud.
    Mocks for testing DataBase.
    Unit-test to testing interface/user_controller.go
    Postman to develop the project.

# Packages Used:
    github.com/caarlos0/env - v3.5.0 (for environment variable management)
    github.com/dgrijalva/jwt-go - v3.2.0 (for JWT token generation and validation)
    github.com/go-playground/validator - v9.31.0 (for request data validation)
    github.com/golang-jwt/jwt - v3.2.2 (for JWT-based authentication)
    github.com/golang/mock - v1.6.0 (for mocking during tests)
    github.com/google/uuid - v1.3.1 (for generating unique user IDs)
    github.com/joho/godotenv - v1.5.1 (for loading environment variables from .env files)
    github.com/labstack/echo - v3.3.10 (for routing and handling HTTP requests)
    github.com/labstack/gommon - v0.4.0 (for common utility functions)
    github.com/sirupsen/logrus - v1.9.3 (for logging)
    github.com/stretchr/testify - v1.8.2 (for unit testing)
    go.mongodb.org/mongo-driver - v1.12.1 (MongoDB Go driver)
    golang.org/x/crypto - v0.0.0-20220622213112 (for cryptographic functions)
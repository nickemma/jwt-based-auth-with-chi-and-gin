package auth_service_gin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	dbPool    *pgxpool.Pool
	jwtSecret = []byte("your_jwt_secret_here")
)

type User struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"-"`
	Role      string `json:"role"`
	Verified  bool   `json:"verified"`
}

func main() {
	// Database setup
	connStr := "postgres://user:pass@localhost:5432/auth_db"
	poolConfig, _ := pgxpool.ParseConfig(connStr)
	dbPool, _ = pgxpool.New(context.Background(), poolConfig.Config.ConnString())

	r := gin.Default()

	// Public routes
	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)
	r.GET("/verify-email", verifyEmailHandler)

	// Protected routes
	auth := r.Group("/")
	auth.Use(JWTMiddleware())
	{
		auth.GET("/user", getUserHandler)
	}

	// Admin routes
	admin := auth.Group("/")
	admin.Use(AdminMiddleware())
	{
		// Add admin-specific routes here
	}

	r.Run(":3000")
}

func registerHandler(c *gin.Context) {
	var user struct {
		FirstName string `json:"first_name" binding:"required"`
		LastName  string `json:"last_name" binding:"required"`
		Email     string `json:"email" binding:"required,email"`
		Password  string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)

	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO users (first_name, last_name, email, password, role, verified)
		VALUES ($1, $2, $3, $4, 'user', false)`,
		user.FirstName, user.LastName, user.Email, string(hashedPassword),
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	// Send verification email
	sendVerificationEmail(user.Email)

	c.JSON(http.StatusCreated, gin.H{"message": "Registration successful"})
}

func loginHandler(c *gin.Context) {
	var credentials struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := dbPool.QueryRow(context.Background(),
		`SELECT id, first_name, last_name, email, password, role, verified 
		FROM users WHERE email = $1`,
		credentials.Email,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password, &user.Role, &user.Verified)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if !user.Verified {
		c.JSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, _ := token.SignedString(jwtSecret)

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func verifyEmailHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}

	// Verify token
	email, valid := validateVerificationToken(token)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	_, err := dbPool.Exec(context.Background(),
		`UPDATE users SET verified = true WHERE email = $1`,
		email,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Verification failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func getUserHandler(c *gin.Context) {
	claims := c.MustGet("claims").(jwt.MapClaims)
	userID := claims["user_id"].(string)

	var user User
	err := dbPool.QueryRow(context.Background(),
		`SELECT id, first_name, last_name, email, role 
		FROM users WHERE id = $1`,
		userID,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Role)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("claims", claims)
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Next()
	}
}

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := c.MustGet("claims").(jwt.MapClaims)
		if claims["role"] != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}
		c.Next()
	}
}

func sendVerificationEmail(email string) {
	// Implement email sending logic
}

func validateVerificationToken(token string) (string, bool) {
	// Implement token validation logic
	return "user@example.com", true
}

package auth_service_chi

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	dbPool    *pgxpool.Pool
	tokenAuth *jwtauth.JWTAuth
	jwtSecret = "your_jwt_secret_here"
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
	tokenAuth = jwtauth.New("HS256", []byte(jwtSecret), nil)

	// Database setup
	connStr := "postgres://user:pass@localhost:5432/auth_db"
	poolConfig, _ := pgxpool.ParseConfig(connStr)
	dbPool, _ = pgxpool.New(context.Background(), poolConfig.Config.ConnString())

	r := chi.NewRouter()

	// Public routes
	r.Post("/register", registerHandler)
	r.Post("/login", loginHandler)
	r.Get("/verify-email", verifyEmailHandler)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)

		r.Get("/user", getUserHandler)
	})

	// Admin routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)
		r.Use(adminOnly)

		// Add admin-specific routes here
	})

	http.ListenAndServe(":3000", r)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)

	_, err := dbPool.Exec(r.Context(),
		`INSERT INTO users (first_name, last_name, email, password, role, verified)
		VALUES ($1, $2, $3, $4, 'user', false)`,
		user.FirstName, user.LastName, user.Email, string(hashedPassword),
	)

	if err != nil {
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	// Send verification email (pseudo-code)
	sendVerificationEmail(user.Email)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	err := dbPool.QueryRow(r.Context(),
		`SELECT id, first_name, last_name, email, password, role, verified 
		FROM users WHERE email = $1`,
		credentials.Email,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password, &user.Role, &user.Verified)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !user.Verified {
		http.Error(w, "Email not verified", http.StatusForbidden)
		return
	}

	// Generate JWT
	claims := map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	}

	_, tokenString, _ := tokenAuth.Encode(claims)

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Verify token (pseudo-code)
	email, valid := validateVerificationToken(token)
	if !valid {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	_, err := dbPool.Exec(r.Context(),
		`UPDATE users SET verified = true WHERE email = $1`,
		email,
	)

	if err != nil {
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Email verified successfully"))
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	userID := claims["user_id"].(string)

	var user User
	err := dbPool.QueryRow(r.Context(),
		`SELECT id, first_name, last_name, email, role 
		FROM users WHERE id = $1`,
		userID,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Role)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["role"] != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Helper functions (implement these)
func sendVerificationEmail(email string) {
	// Implement email sending logic
}

func validateVerificationToken(token string) (string, bool) {
	// Implement token validation logic
	return "user@example.com", true
}

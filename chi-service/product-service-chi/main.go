package product_service_chi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	dbPool    *pgxpool.Pool
	tokenAuth = jwtauth.New("HS256", []byte("your_jwt_secret_here"), nil)
)

type Product struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	ImageURL    string  `json:"image_url"`
}

func main() {
	connStr := "postgres://user:pass@localhost:5432/product_db"
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse config: %v", err))
	}

	dbPool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		panic(fmt.Sprintf("Unable to create connection pool: %v", err))
	}

	r := chi.NewRouter()

	// Public routes
	r.Get("/products", getProductsHandler)

	// Admin protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator(tokenAuth))
		r.Use(adminOnly)

		r.Post("/products", createProductHandler)
	})

	http.ListenAndServe(":3001", r)
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

func createProductHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	userID := claims["user_id"].(string)

	var product struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Price       float64 `json:"price"`
		ImageURL    string  `json:"image_url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_, err := dbPool.Exec(r.Context(),
		`INSERT INTO products (title, description, price, image_url, created_by)
		VALUES ($1, $2, $3, $4, $5)`,
		product.Title, product.Description, product.Price, product.ImageURL, userID,
	)

	if err != nil {
		http.Error(w, "Product creation failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(product)
}

func getProductsHandler(w http.ResponseWriter, r *http.Request) {
	rows, _ := dbPool.Query(r.Context(), "SELECT * FROM products")
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Price, &p.ImageURL)
		products = append(products, p)
	}

	json.NewEncoder(w).Encode(products)
}

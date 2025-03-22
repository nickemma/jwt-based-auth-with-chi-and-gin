package product_service_chi

import (
	"context"
	"encoding/json"
	"net/http"

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
	poolConfig, _ := pgxpool.ParseConfig(connStr)
	dbPool, _ = pgxpool.New(context.Background(), poolConfig.Config.ConnString())

	r := chi.NewRouter()

	// Public routes
	r.Get("/products", getProductsHandler)

	// Admin protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)
		r.Use(adminOnly)

		r.Post("/products", createProductHandler)
	})

	http.ListenAndServe(":3001", r)
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

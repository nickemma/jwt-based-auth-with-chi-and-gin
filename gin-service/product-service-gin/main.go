package product_service_gin

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	dbPool *pgxpool.Pool
)

type Product struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	ImageURL    string  `json:"image_url"`
}

func main() {
	// Database setup
	connStr := "postgres://user:pass@localhost:5432/product_db"
	poolConfig, _ := pgxpool.ParseConfig(connStr)
	dbPool, _ = pgxpool.New(context.Background(), poolConfig.Config.ConnString())

	r := gin.Default()

	// Public routes
	r.GET("/products", getProductsHandler)

	// Admin protected routes
	admin := r.Group("/")
	admin.Use(JWTMiddleware())
	admin.Use(AdminMiddleware())
	{
		admin.POST("/products", createProductHandler)
	}

	r.Run(":3001")
}

func createProductHandler(c *gin.Context) {
	claims := c.MustGet("claims").(jwt.MapClaims)
	userID := claims["user_id"].(string)

	var product struct {
		Title       string  `json:"title" binding:"required"`
		Description string  `json:"description"`
		Price       float64 `json:"price" binding:"required"`
		ImageURL    string  `json:"image_url"`
	}

	if err := c.ShouldBindJSON(&product); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO products (title, description, price, image_url, created_by)
		VALUES ($1, $2, $3, $4, $5)`,
		product.Title, product.Description, product.Price, product.ImageURL, userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Product creation failed"})
		return
	}

	c.JSON(http.StatusCreated, product)
}

func getProductsHandler(c *gin.Context) {
	rows, _ := dbPool.Query(context.Background(), "SELECT * FROM products")
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Price, &p.ImageURL)
		products = append(products, p)
	}

	c.JSON(http.StatusOK, products)
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("your_jwt_secret_here"), nil
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

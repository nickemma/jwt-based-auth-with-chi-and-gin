# Go Microservices with Chi and Gin
Secure Microservices with JWT Auth and Role-Based Access

Two implementations of a microservices architecture using:
- Chi Router (+ jwtauth)
- Gin Framework (+ native JWT)

## Features

**Common Features (Both Implementations):**
- 🔐 JWT Authentication with Refresh Tokens
- 👥 Role-Based Access Control (User/Admin)
- ✉️ Email Verification (Placeholder Implementation)
- 🛡️ Protected Routes Middleware
- 🧩 Microservices Architecture
    - Auth Service (User Management)
    - Product Service (CRUD Operations)
- 🐘 PostgreSQL Data Storage
- 🔄 REST API Endpoints

**Chi-Specific:**
- 🚀 Chi Router with jwtauth middleware
- 🧰 pgx PostgreSQL driver
- ⚡ Lightweight implementation

**Gin-Specific:**
- 🚄 Gin Framework with native JWT
- 🛠️ Built-in validation system
- 📦 Context-based middleware

## Prerequisites

1. Go 1.20+
2. PostgreSQL 14+
3. Make (optional)
4. curl/httpie (for testing)

## Getting Started

### 1. Clone Repository
```bash
git clone https://github.com/yourrepo/go-auth-microservices
cd go-auth-microservices
```
### 2. Database Setup
```
-- Run in both auth_db and product_db
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK (role IN ('user', 'admin')) NOT NULL,
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    image_url TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 3. Configuration
Create .env files:

```
# auth-service/.env
DB_URL=postgres://user:pass@localhost:5432/auth_db
JWT_SECRET=your_secure_secret_here
SMTP_HOST=smtp.example.com # Placeholder
```

## Chi Implementation
Structure
```
/chi-implementation
  /auth-service
  /product-service
```
Running Services
```
# Auth Service
cd chi-implementation/auth-service
go run main.go -port 3000

# Product Service (separate terminal)
cd chi-implementation/product-service
go run main.go -port 3001
```
### Endpoints
- Method	Path	Access	Description
- POST	/register	Public	User registration
- POST	/login	Public	JWT authentication
- GET	/user	User	Get current user
- POST	/products	Admin	Create product
- GET	/products	Public	List products

## Gin Implementation
Structure
```
/gin-implementation
  /auth-service
  /product-service
```
Running Services
```
# Auth Service
cd gin-implementation/auth-service
go run main.go -port 4000

# Product Service
cd gin-implementation/product-service
go run main.go -port 4001
```

### Key Differences from Chi
- Uses Gin's native context handling
- Built-in validation system
- Different middleware structure
- Response formatting helpers

### Testing the API
### 1. Register User
```
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securePass123"
  }'
```
### 2. Login
```
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@example.com", "password": "securePass123"}'
```
### 3. Access Protected Route
```
curl -H "Authorization: Bearer <JWT_TOKEN>" http://localhost:3000/user
```
### 4. Admin Product Creation
```
curl -X POST http://localhost:3001/products \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Premium Widget",
    "price": 99.99,
    "description": "High-quality widget"
  }'
```
## Contributing
1. Fork the repository
2. Create feature branch
3. Submit PR with tests
4. Follow Go code style guidelines

## License
MIT License - See LICENSE file



# Auth Service

A production-ready authentication microservice built with Node.js, Express, MongoDB, and JWT tokens. Handles user registration, authentication, role-based access control, and user management.

## 🚀 Features

- **User Registration & Authentication** with email/password
- **JWT Token-based Authentication** with configurable expiration
- **Role-based Access Control** (school, teacher, vendor, admin)
- **Email Verification** and admin approval workflows
- **Rate Limiting** for security
- **Input Validation** and comprehensive error handling
- **MongoDB Integration** with Mongoose ODM

## 📋 User Roles

- **school**: School administrators
- **teacher**: Individual teachers
- **vendor**: Service/product vendors
- **admin**: System administrators (auto-approved)

## 🛠️ Setup

### Prerequisites

- Node.js 16+
- MongoDB 4.4+
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Update the following variables in `.env`:
   - `MONGO_URI`: Your MongoDB connection string
   - `JWT_SECRET`: A secure random string (32+ characters)
   - `JWT_EXPIRE`: Token expiration time (default: 7d)
   - `PORT`: Server port (default: 3000)

4. Start the service:
   ```bash
   # Development
   npm run dev
   
   # Production
   npm start
   ```

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api/auth
```

### Authentication Headers
For protected routes, include the JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

### Endpoints

#### 1. User Registration
```http
POST /signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "role": "teacher"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "_id": "...",
      "email": "user@example.com",
      "role": "teacher",
      "isVerified": false,
      "approvedByAdmin": false,
      "createdAt": "...",
      "updatedAt": "..."
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "verificationToken": "abc123..."
  }
}
```

#### 2. User Login
```http
POST /login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "_id": "...",
      "email": "user@example.com",
      "role": "teacher",
      "isVerified": true,
      "approvedByAdmin": true
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### 3. Email Verification
```http
POST /verify
Content-Type: application/json

{
  "email": "user@example.com",
  "verificationToken": "abc123..."
}
```

#### 4. Get User Profile
```http
GET /me
Authorization: Bearer <jwt-token>
```

#### 5. Admin Approve User
```http
PUT /approve/:userId
Authorization: Bearer <admin-jwt-token>
```

#### 6. List Users (Admin Only)
```http
GET /users?page=1&limit=10&role=teacher&isVerified=true
Authorization: Bearer <admin-jwt-token>
```

### Error Responses

All error responses follow this format:
```json
{
  "success": false,
  "message": "Error description",
  "errors": [] // Optional validation errors
}
```

Common HTTP status codes:
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (invalid/missing token)
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found
- `429`: Too Many Requests (rate limited)
- `500`: Internal Server Error

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_URI` | MongoDB connection string | Required |
| `JWT_SECRET` | Secret key for JWT signing | Required |
| `JWT_EXPIRE` | JWT token expiration time | `7d` |
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment mode | `development` |

## 🏥 Health Check

Check service status:
```http
GET /health
```

Response:
```json
{
  "success": true,
  "message": "Auth Service is running",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "version": "1.0.0"
}
```

## 🔒 Security Features

- **Password Hashing**: bcrypt with salt rounds of 12
- **Rate Limiting**: 5 auth attempts per 15 minutes per IP
- **JWT Security**: Configurable expiration and secure signing
- **Input Validation**: Comprehensive validation with express-validator
- **CORS Protection**: Configurable cross-origin resource sharing
- **Error Handling**: Sanitized error responses without sensitive data

## 📊 User Workflow

1. **Registration**: User signs up with email, password, and role
2. **Verification**: User verifies email (token provided in response)
3. **Admin Approval**: Admin approves non-admin accounts
4. **Authentication**: User can login and receive JWT token
5. **Access**: User can access protected resources with valid token

## 🚀 Deployment

### Docker (Recommended)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment-specific configurations
- **Development**: Use `npm run dev` with nodemon
- **Production**: Use `npm start` with PM2 or similar process manager
- **Testing**: Set `NODE_ENV=test` and use test database

## 📈 Monitoring

Monitor these key metrics:
- Authentication success/failure rates
- Token validation performance
- Database connection health
- API response times
- Rate limiting triggers

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details
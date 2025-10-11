# Auth Service Integration Guide

This document explains how to integrate the Auth Service with frontend applications and backend microservices.

## 🌐 Frontend Integration

### React/Vue/Angular Applications

#### 1. Authentication Flow

```javascript
// API client setup
const API_BASE_URL = 'http://localhost:3000/api/auth';

class AuthService {
  constructor() {
    this.token = localStorage.getItem('authToken');
  }

  // User Registration
  async signup(userData) {
    try {
      const response = await fetch(`${API_BASE_URL}/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData)
      });

      const data = await response.json();
      
      if (data.success) {
        this.setToken(data.data.token);
        return data.data;
      } else {
        throw new Error(data.message);
      }
    } catch (error) {
      console.error('Signup error:', error);
      throw error;
    }
  }

  // User Login
  async login(email, password) {
    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();
      
      if (data.success) {
        this.setToken(data.data.token);
        return data.data;
      } else {
        throw new Error(data.message);
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  // Get Current User
  async getCurrentUser() {
    if (!this.token) {
      throw new Error('No authentication token');
    }

    try {
      const response = await fetch(`${API_BASE_URL}/me`, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
        }
      });

      const data = await response.json();
      
      if (data.success) {
        return data.data.user;
      } else {
        throw new Error(data.message);
      }
    } catch (error) {
      console.error('Get user error:', error);
      this.logout(); // Clear invalid token
      throw error;
    }
  }

  // Email Verification
  async verifyEmail(email, verificationToken) {
    try {
      const response = await fetch(`${API_BASE_URL}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, verificationToken })
      });

      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.message);
      }
      
      return data.data;
    } catch (error) {
      console.error('Verification error:', error);
      throw error;
    }
  }

  // Token Management
  setToken(token) {
    this.token = token;
    localStorage.setItem('authToken', token);
  }

  getToken() {
    return this.token;
  }

  logout() {
    this.token = null;
    localStorage.removeItem('authToken');
  }

  isAuthenticated() {
    return !!this.token;
  }
}

// Export singleton instance
export const authService = new AuthService();
```

#### 2. React Hook Example

```javascript
// useAuth.js
import { useState, useEffect, useContext, createContext } from 'react';
import { authService } from './authService';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      if (authService.isAuthenticated()) {
        const userData = await authService.getCurrentUser();
        setUser(userData);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      setLoading(true);
      setError(null);
      const { user } = await authService.login(email, password);
      setUser(user);
      return user;
    } catch (error) {
      setError(error.message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signup = async (userData) => {
    try {
      setLoading(true);
      setError(null);
      const { user } = await authService.signup(userData);
      setUser(user);
      return user;
    } catch (error) {
      setError(error.message);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setError(null);
  };

  const value = {
    user,
    loading,
    error,
    login,
    signup,
    logout,
    isAuthenticated: !!user,
    hasRole: (role) => user?.role === role,
    isVerified: user?.isVerified || false,
    isApproved: user?.approvedByAdmin || false
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

#### 3. Protected Route Component

```javascript
// ProtectedRoute.js
import { useAuth } from './useAuth';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children, requiredRole, requireVerification = true, requireApproval = true }) => {
  const { user, loading, isAuthenticated } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requireVerification && !user.isVerified) {
    return <Navigate to="/verify-email" replace />;
  }

  if (requireApproval && !user.approvedByAdmin && user.role !== 'admin') {
    return <Navigate to="/pending-approval" replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    return <Navigate to="/unauthorized" replace />;
  }

  return children;
};

export default ProtectedRoute;
```

#### 4. HTTP Interceptor for API Calls

```javascript
// apiClient.js
import { authService } from './authService';

class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const token = authService.getToken();

    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    // Add auth header if token exists
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      // Handle token expiration
      if (response.status === 401 && data.message === 'Token expired') {
        authService.logout();
        window.location.href = '/login';
        return;
      }

      if (!response.ok) {
        throw new Error(data.message || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  }

  post(endpoint, data, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  put(endpoint, data, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }
}

export const apiClient = new ApiClient('http://localhost:3000/api');
```

## 🔧 Backend Microservice Integration

### Node.js/Express Services

#### 1. JWT Verification Middleware

```javascript
// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Optionally verify user still exists by calling Auth Service
      const userResponse = await fetch(`${process.env.AUTH_SERVICE_URL}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!userResponse.ok) {
        return res.status(401).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const userData = await userResponse.json();
      req.user = userData.data.user;
      next();
    } catch (jwtError) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during authentication'
    });
  }
};

// Role-based authorization
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${roles.join(', ')}`
      });
    }

    next();
  };
};

module.exports = { verifyToken, requireRole };
```

#### 2. Auth Service Client

```javascript
// services/authServiceClient.js
class AuthServiceClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }

  async validateToken(token) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return data.data.user;
    } catch (error) {
      console.error('Token validation error:', error);
      return null;
    }
  }

  async getUserById(userId, adminToken) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/users?_id=${userId}`, {
        headers: {
          'Authorization': `Bearer ${adminToken}`
        }
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return data.data.users[0] || null;
    } catch (error) {
      console.error('Get user error:', error);
      return null;
    }
  }

  async approveUser(userId, adminToken) {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/approve/${userId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${adminToken}`
        }
      });

      if (!response.ok) {
        return false;
      }

      return true;
    } catch (error) {
      console.error('Approve user error:', error);
      return false;
    }
  }
}

module.exports = new AuthServiceClient(process.env.AUTH_SERVICE_URL || 'http://localhost:3000');
```

#### 3. Example Service Integration

```javascript
// routes/schoolRoutes.js
const express = require('express');
const { verifyToken, requireRole } = require('../middleware/authMiddleware');
const authServiceClient = require('../services/authServiceClient');

const router = express.Router();

// Only schools can create school profiles
router.post('/profile', verifyToken, requireRole('school'), async (req, res) => {
  try {
    // req.user contains the authenticated user data
    const schoolData = {
      ...req.body,
      userId: req.user._id,
      userEmail: req.user.email
    };

    // Create school profile logic here
    // ...

    res.json({
      success: true,
      message: 'School profile created successfully',
      data: schoolData
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating school profile'
    });
  }
});

// Admins can view all schools
router.get('/all', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    // Get all schools logic here
    // ...

    res.json({
      success: true,
      data: schools
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching schools'
    });
  }
});

module.exports = router;
```

### Python/Django Services

#### 1. JWT Verification Decorator

```python
# auth_middleware.py
import jwt
import requests
from functools import wraps
from django.http import JsonResponse
from django.conf import settings

def verify_token(required_roles=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({
                    'success': False,
                    'message': 'Access denied. No token provided.'
                }, status=401)

            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            try:
                # Verify token with Auth Service
                response = requests.get(
                    f"{settings.AUTH_SERVICE_URL}/api/auth/me",
                    headers={'Authorization': f'Bearer {token}'}
                )
                
                if response.status_code != 200:
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid token'
                    }, status=401)
                
                user_data = response.json()['data']['user']
                
                # Check role requirements
                if required_roles and user_data['role'] not in required_roles:
                    return JsonResponse({
                        'success': False,
                        'message': f'Access denied. Required roles: {", ".join(required_roles)}'
                    }, status=403)
                
                # Add user data to request
                request.user_data = user_data
                
                return view_func(request, *args, **kwargs)
                
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': 'Authentication error'
                }, status=500)
        
        return wrapper
    return decorator
```

#### 2. Django View Example

```python
# views.py
from django.http import JsonResponse
from .auth_middleware import verify_token

@verify_token(required_roles=['teacher', 'admin'])
def create_lesson(request):
    if request.method == 'POST':
        # request.user_data contains authenticated user info
        user = request.user_data
        
        # Create lesson logic here
        lesson_data = {
            'title': request.POST.get('title'),
            'teacher_id': user['_id'],
            'teacher_email': user['email']
        }
        
        return JsonResponse({
            'success': True,
            'message': 'Lesson created successfully',
            'data': lesson_data
        })
```

## 🔄 Service-to-Service Communication

### 1. Admin Service Integration

```javascript
// Admin service calling Auth service for user management
const authServiceClient = require('./authServiceClient');

class AdminService {
  async approveUser(userId, adminToken) {
    // Validate admin token first
    const admin = await authServiceClient.validateToken(adminToken);
    if (!admin || admin.role !== 'admin') {
      throw new Error('Unauthorized');
    }

    // Approve user via Auth service
    const success = await authServiceClient.approveUser(userId, adminToken);
    if (!success) {
      throw new Error('Failed to approve user');
    }

    // Additional admin service logic...
    return { success: true, message: 'User approved successfully' };
  }

  async getUserStats(adminToken) {
    // Get user statistics from Auth service
    const response = await fetch(`${process.env.AUTH_SERVICE_URL}/api/auth/users`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });

    const data = await response.json();
    return {
      totalUsers: data.data.pagination.total,
      usersByRole: this.groupUsersByRole(data.data.users)
    };
  }
}
```

### 2. Environment Configuration

```bash
# .env for other services
AUTH_SERVICE_URL=http://auth-service:3000
JWT_SECRET=your-shared-jwt-secret
```

## 🚨 Error Handling

### Common Error Scenarios

1. **Token Expired**: Redirect to login
2. **Invalid Token**: Clear token and redirect to login
3. **Insufficient Permissions**: Show access denied page
4. **Service Unavailable**: Show maintenance message

### Frontend Error Handling

```javascript
// Global error handler
const handleAuthError = (error) => {
  if (error.message.includes('Token expired') || error.message.includes('Invalid token')) {
    authService.logout();
    window.location.href = '/login';
  } else if (error.message.includes('Access denied')) {
    window.location.href = '/unauthorized';
  } else {
    // Show generic error message
    console.error('Auth error:', error);
  }
};
```

## 🔒 Security Best Practices

1. **Always use HTTPS** in production
2. **Store JWT tokens securely** (httpOnly cookies preferred over localStorage)
3. **Implement token refresh** for long-lived sessions
4. **Validate tokens on every request** in backend services
5. **Use environment variables** for sensitive configuration
6. **Implement proper CORS** policies
7. **Add request logging** for security monitoring
8. **Use rate limiting** to prevent abuse

## 📊 Monitoring Integration

Monitor these metrics across services:
- Authentication success/failure rates
- Token validation performance
- Service-to-service communication health
- User role distribution
- API endpoint usage patterns

This integration guide provides everything needed to securely connect your frontend applications and backend microservices with the Auth Service.
# Money Manager Application - Project Summary

## Project Overview
**Project Name:** Money Manager  
**Technology Stack:** Spring Boot 3.5.3, Java 21, PostgreSQL, JWT Authentication, React (Frontend)  
**Architecture:** RESTful API with JWT-based authentication, Multi-tier architecture  
**Deployment:** Docker containerized with multi-stage build  

## Core Features

### 1. User Authentication & Authorization
- **JWT-based Authentication** with stateless session management
- **User Registration** with email verification system
- **Account Activation** via email tokens
- **Password Encryption** using BCrypt
- **Role-based Access Control** for secure API endpoints

### 2. Financial Transaction Management
- **Income Tracking**: Add, view, and delete income transactions
- **Expense Tracking**: Add, view, and delete expense transactions
- **Category Management**: Create and manage custom categories for income/expenses
- **Transaction Filtering**: Advanced filtering by date range, keywords, and sorting options

### 3. Dashboard & Analytics
- **Real-time Dashboard** with financial overview
- **Monthly Transaction Views** for current month data
- **Data Visualization** capabilities for financial insights

### 4. Data Export & Reporting
- **Excel Export** functionality for income and expense data
- **Monthly Reports** generation in .xlsx format
- **Data Filtering** before export for customized reports

### 5. Email Integration
- **Account Activation** emails via Brevo SMTP service
- **Automated Email Notifications** for user registration
- **Email Templates** for professional communication

## Technical Architecture

### Backend (Spring Boot)
```
├── Controllers (REST API Layer)
│   ├── ProfileController - User management & authentication
│   ├── ExpenseController - Expense CRUD operations
│   ├── IncomeController - Income CRUD operations
│   ├── CategoryController - Category management
│   ├── DashboardController - Analytics & overview
│   ├── FilterController - Advanced filtering
│   ├── ExcelController - Data export functionality
│   └── EmailController - Email services
├── Services (Business Logic Layer)
│   ├── ProfileService - User authentication & management
│   ├── ExpenseService - Expense business logic
│   ├── IncomeService - Income business logic
│   ├── CategoryService - Category management
│   ├── DashboardService - Analytics processing
│   ├── ExcelService - Report generation
│   └── EmailService - Email functionality
├── Entities (Data Model Layer)
│   ├── ProfileEntity - User profile data
│   ├── ExpenseEntity - Expense transactions
│   ├── IncomeEntity - Income transactions
│   └── CategoryEntity - Transaction categories
├── Security (Authentication & Authorization)
│   ├── JwtRequestFilter - JWT token validation
│   ├── SecurityConfig - CORS & security configuration
│   └── JwtUtil - JWT token generation & validation
└── Configuration
    ├── Database configuration (PostgreSQL)
    ├── Email configuration (Brevo SMTP)
    └── CORS configuration for frontend integration
```

### Database Schema
- **PostgreSQL** as primary database
- **JPA/Hibernate** for ORM mapping
- **Entity Relationships**: Many-to-One relationships between transactions and users/categories
- **Audit Fields**: Created/Updated timestamps for all entities
- **Data Integrity**: Foreign key constraints and unique constraints

### Security Implementation
- **JWT Tokens** for stateless authentication
- **CORS Configuration** for cross-origin requests
- **Password Hashing** using BCrypt
- **Email Verification** for account activation
- **Role-based Access Control** for API endpoints

### Frontend Integration
- **React Application** (Port 5173)
- **RESTful API Communication** with backend
- **JWT Token Management** for authenticated requests
- **Responsive UI** for cross-platform compatibility

## API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User authentication
- `GET /activate` - Account activation
- `GET /profile` - Get user profile

### Financial Management
- `POST /expenses` - Add expense
- `GET /expenses` - Get current month expenses
- `DELETE /expenses/{id}` - Delete expense
- `POST /incomes` - Add income
- `GET /incomes` - Get current month incomes
- `DELETE /incomes/{id}` - Delete income

### Categories
- `POST /categories` - Create category
- `GET /categories` - Get user categories
- `GET /categories/{type}` - Get categories by type
- `PUT /categories/{id}` - Update category

### Analytics & Reports
- `GET /dashboard` - Get dashboard data
- `POST /filter` - Filter transactions
- `GET /excel/download/income` - Export income to Excel
- `GET /excel/download/expense` - Export expense to Excel

## Deployment Configuration

### Docker Setup
- **Multi-stage Build** for optimized container size
- **Java 21 Runtime** environment
- **Port 8080** exposure
- **JAR file** deployment strategy

### Environment Configuration
- **Development**: Local PostgreSQL database
- **Production**: Environment-specific database configuration
- **Email Service**: Brevo SMTP integration
- **Frontend URL**: Configurable for different environments

## Key Technical Achievements

1. **Scalable Architecture**: Clean separation of concerns with layered architecture
2. **Security First**: JWT authentication with email verification
3. **Data Integrity**: Proper entity relationships and constraints
4. **Export Functionality**: Excel report generation using Apache POI
5. **Filtering System**: Advanced transaction filtering with multiple criteria
6. **Docker Ready**: Containerized application for easy deployment
7. **CORS Enabled**: Frontend-backend integration ready
8. **Email Integration**: Professional email service integration

## Performance Considerations
- **Lazy Loading** for entity relationships
- **Database Indexing** on frequently queried fields
- **JWT Stateless Authentication** for scalability
- **Efficient Querying** with JPA repositories
- **Docker Optimization** with multi-stage builds

## Future Enhancement Opportunities
- Real-time notifications
- Advanced analytics and charts
- Mobile application development
- Multi-currency support
- Budget planning features
- Investment tracking
- Bill reminders and automation

---

**Developer:** ROSHAN  
**Project Duration:** [Your timeline]  
**Technologies Used:** Spring Boot, Java 21, PostgreSQL, JWT, Docker, React, Apache POI, Brevo Email Service

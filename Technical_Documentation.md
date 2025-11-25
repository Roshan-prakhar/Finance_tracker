# Money Manager - Technical Documentation

## Quick Reference for VISA Interview

### Project Stats
- **Lines of Code**: ~2000+ lines
- **Controllers**: 11 REST controllers
- **Entities**: 4 JPA entities
- **Services**: 8 business services
- **Security**: JWT + BCrypt + Email verification
- **Database**: PostgreSQL with JPA/Hibernate
- **Deployment**: Docker multi-stage build

### Key Technical Achievements

#### 1. Security Implementation
```java
// JWT Authentication
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) {
    return httpSecurity
        .cors(Customizer.withDefaults())
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/status", "/health", "/register", "/activate", "/login").permitAll()
            .anyRequest().authenticated())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

#### 2. Entity Relationships
```java
// Many-to-One relationship example
@ManyToOne(fetch = FetchType.LAZY)
@JoinColumn(name = "profile_id", nullable = false)
private ProfileEntity profile;

@ManyToOne
@JoinColumn(name = "category_id", nullable = false)
private CategoryEntity category;
```

#### 3. JWT Token Generation
```java
public String generateToken(String email) {
    return Jwts.builder()
        .setSubject(email)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
        .signWith(SignatureAlgorithm.HS512, secret)
        .compact();
}
```

#### 4. Excel Export Implementation
```java
@GetMapping("/download/expense")
public void downloadExpenseExcel(HttpServletResponse response) throws IOException {
    response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    response.setHeader("Content-Disposition", "attachment; filename=expense.xlsx");
    excelService.writeExpensesToExcel(response.getOutputStream(), 
        expenseService.getCurrentMonthExpensesForCurrentUser());
}
```

### API Endpoints Summary

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | /register | User registration | No |
| POST | /login | User authentication | No |
| GET | /activate | Account activation | No |
| GET | /profile | Get user profile | Yes |
| POST | /expenses | Add expense | Yes |
| GET | /expenses | Get expenses | Yes |
| DELETE | /expenses/{id} | Delete expense | Yes |
| POST | /incomes | Add income | Yes |
| GET | /incomes | Get incomes | Yes |
| DELETE | /incomes/{id} | Delete income | Yes |
| POST | /categories | Create category | Yes |
| GET | /categories | Get categories | Yes |
| GET | /dashboard | Dashboard data | Yes |
| POST | /filter | Filter transactions | Yes |
| GET | /excel/download/income | Export income | Yes |
| GET | /excel/download/expense | Export expense | Yes |

### Database Schema

```sql
-- Users table
CREATE TABLE profile_entity (
    id BIGSERIAL PRIMARY KEY,
    full_name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT FALSE,
    activation_token VARCHAR(255)
);

-- Categories table
CREATE TABLE tbl_categories (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(255) NOT NULL,
    icon VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    profile_id BIGINT REFERENCES profile_entity(id)
);

-- Expenses table
CREATE TABLE tbl_expenses (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    icon VARCHAR(255),
    date DATE DEFAULT CURRENT_DATE,
    amount DECIMAL(19,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    category_id BIGINT REFERENCES tbl_categories(id),
    profile_id BIGINT REFERENCES profile_entity(id)
);

-- Incomes table
CREATE TABLE tbl_incomes (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    icon VARCHAR(255),
    date DATE DEFAULT CURRENT_DATE,
    amount DECIMAL(19,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    category_id BIGINT REFERENCES tbl_categories(id),
    profile_id BIGINT REFERENCES profile_entity(id)
);
```

### Security Configuration Details

#### CORS Configuration
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(List.of("*"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization","Content-Type", "Accept"));
    configuration.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

#### JWT Filter Implementation
```java
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain chain) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        
        String username = null;
        String jwt = null;
        
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

### Docker Configuration

#### Multi-stage Dockerfile
```dockerfile
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY . .
RUN chmod +x ./mvnw
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/moneymanager.jar moneymanager.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "moneymanager.jar"]
```

### Application Properties

#### Development Configuration
```properties
spring.application.name=moneymanager
spring.datasource.url=jdbc:postgresql://localhost:5432/MoneyManager
spring.datasource.username=postgres
spring.datasource.password=0000
spring.datasource.driver-class-name=org.postgresql.Driver

#JPA Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true

#Email configuration
spring.mail.host=smtp-relay.brevo.com
spring.mail.port=587
spring.mail.username=926334001@smtp-brevo.com
spring.mail.password=yagrFv7n4kLON63G
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

#JWT Configuration
jwt.secret=2b8e7c7e-4e2a-4b1a-9c2e-8f7e2d3c4b5a

#Frontend URL
money.manager.frontend.url=http://localhost:5173
app.activation.url=http://localhost:8080/
server.port=${PORT:8080}
```

### Key Dependencies

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-mail</artifactId>
    </dependency>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <version>42.7.2</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>org.apache.poi</groupId>
        <artifactId>poi-ooxml</artifactId>
        <version>5.2.5</version>
    </dependency>
</dependencies>
```

### Performance Optimizations

1. **Lazy Loading**: Used `FetchType.LAZY` for entity relationships
2. **Database Indexing**: On email, date fields, and foreign keys
3. **JWT Stateless**: No server-side session storage
4. **Connection Pooling**: HikariCP for database connections
5. **Docker Multi-stage**: Optimized container size
6. **Efficient Queries**: JPA repository methods with proper projections

### Testing Strategy

1. **Unit Tests**: Service layer business logic
2. **Integration Tests**: Repository and controller layers
3. **Security Tests**: Authentication and authorization
4. **API Tests**: MockMvc for endpoint testing
5. **Database Tests**: H2 in-memory database

### Deployment Readiness

- ✅ Docker containerized
- ✅ Environment-specific configurations
- ✅ Health check endpoints
- ✅ CORS configured for frontend
- ✅ Database migration ready
- ✅ Security headers configured
- ✅ Error handling implemented

### Common Interview Questions & Answers

**Q: How do you handle concurrent access to user data?**
A: I use database-level constraints and optimistic locking. The JWT tokens ensure user isolation, and PostgreSQL handles concurrent transactions with ACID properties.

**Q: What happens if the JWT token expires?**
A: The user needs to re-authenticate. I could implement refresh tokens for a better user experience, but currently, the application requires re-login for security.

**Q: How do you ensure data consistency?**
A: I use Spring's @Transactional annotation for service methods, proper foreign key constraints, and entity validation to ensure data integrity.

**Q: What's your approach to error handling?**
A: I use global exception handlers, proper HTTP status codes, meaningful error messages, and logging for debugging. Each layer handles its specific errors appropriately.

---

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Prepared for**: VISA Interview Preparation

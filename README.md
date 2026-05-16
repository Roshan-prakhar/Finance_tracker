# Finve — Money Manager (Backend)

A robust **Spring Boot 3.5 + Java 21** REST API powering the Finve personal finance tracker. Handles authentication (JWT + Google OAuth2), transactions, categories, analytics, Excel export, and more.

🔗 **Live API:** https://finance-tracker-4lpe.onrender.com
🔗 **Frontend:** (finance-tracker-28.netlify.app/)

---

## ✨ Features

- 🔐 **JWT Authentication** with Spring Security
- 🔑 **Google OAuth 2.0 Login** (conditional — activates when credentials are set)
- 👤 User registration, profile management
- 📊 **Dashboard analytics** — aggregated balance, income, expense, recent transactions
- 💰 **Income & Expense CRUD** with user‑scoped isolation
- 🗂️ **Categories** — 15 starter categories auto‑seeded on signup
- 🔍 **Advanced filtering** — by type, date range, keywords, sorting
- 📥 **Excel export** via Apache POI
- 🗄️ Works with **H2 (dev)** or **PostgreSQL (prod)**
- 🌐 CORS configured for Netlify + localhost

---

## 🛠️ Tech Stack

| Layer | Tech |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.5.3 |
| Security | Spring Security + JWT (jjwt 0.11.5) + OAuth2 Client |
| Persistence | Spring Data JPA + Hibernate |
| Database | H2 (dev) / PostgreSQL (prod) |
| Excel | Apache POI |
| Build | Maven |
| Deploy | Render (Dockerized) |

---

## 🚀 Getting Started

### Prerequisites
- JDK 21
- Maven 3.9+ (wrapper included)

### Clone & Run

```bash
git clone https://github.com/Roshan-prakhar/Finance_tracker.git
cd Finance_tracker
./mvnw spring-boot:run
```

The server starts on **http://localhost:8080**.

### Environment Variables

Create `src/main/resources/application.properties` (gitignored) or set env vars:

```properties
# JWT
JWT_SECRET=your-long-random-secret

# Frontend (used by OAuth redirects & CORS)
money.manager.frontend.url=http://localhost:5173

# Database (leave blank for default H2)
spring.datasource.url=jdbc:h2:mem:moneymanager
spring.datasource.username=sa
spring.datasource.password=

# Google OAuth (optional — only enables OAuth when all are set)
spring.security.oauth2.client.registration.google.client-id=YOUR_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_CLIENT_SECRET
spring.security.oauth2.client.registration.google.scope=email,profile
spring.security.oauth2.client.registration.google.redirect-uri={baseUrl}/login/oauth2/code/google
```

---

## 📁 Project Structure

```
src/main/java/in/ROSHAN/moneymanager/
├── config/              # SecurityConfig (JWT + OAuth2), CORS
├── controller/          # REST endpoints
│   ├── ProfileController, RootController (/, /health, /status)
│   ├── CategoryController, IncomeController, ExpenseController
│   ├── DashboardController, FilterController
│   ├── ExcelController, EmailController
├── dto/                 # Request/response DTOs
├── entity/              # JPA entities (Profile, Category, Income, Expense)
├── repository/          # Spring Data JPA repositories
├── security/
│   ├── JwtRequestFilter          # Validates JWT on each request
│   └── OAuth2LoginSuccessHandler # Issues JWT after Google login
├── service/             # Business logic (ProfileService, etc.)
└── util/                # JwtUtil and helpers
```

---

## 🔐 Authentication

### JWT Flow
1. `POST /login` with `{ email, password }` → returns `{ token, user }`
2. Client sends `Authorization: Bearer <token>` on subsequent requests
3. `JwtRequestFilter` validates the token and sets the security context

### Google OAuth 2.0 Flow
1. Client hits `GET /oauth2/authorization/google`
2. Spring redirects to Google → user consents
3. Google calls back to `/login/oauth2/code/google`
4. `OAuth2LoginSuccessHandler`:
   - Finds or creates the `ProfileEntity` (and seeds 15 default categories)
   - Generates a JWT
   - Redirects to `${FRONTEND_URL}/oauth-callback?token=<jwt>`

> ⚠️ OAuth2 login activates **only** when a `ClientRegistrationRepository` bean is present (i.e., Google credentials are configured). Otherwise the app starts in JWT‑only mode.

---

## 📡 Key API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` `/health` `/status` | ❌ | Health checks |
| POST | `/register` | ❌ | Create account |
| POST | `/login` | ❌ | Email/password login |
| GET | `/profile` | ✅ | Current user |
| GET | `/categories` | ✅ | List categories |
| POST | `/categories` | ✅ | Create category |
| PUT | `/categories/{id}` | ✅ | Update category |
| GET/POST | `/incomes` | ✅ | Income CRUD |
| DELETE | `/incomes/{id}` | ✅ | Delete income |
| GET/POST | `/expenses` | ✅ | Expense CRUD |
| DELETE | `/expenses/{id}` | ✅ | Delete expense |
| GET | `/dashboard` | ✅ | Aggregated summary |
| POST | `/filter` | ✅ | Filter transactions |
| GET | `/excel/download/income` | ✅ | Export income to Excel |
| GET | `/excel/download/expense` | ✅ | Export expense to Excel |
| GET | `/oauth2/authorization/google` | ❌ | Start Google OAuth |

---

## 🌐 Deployment (Render)

The backend is deployed on Render as a Docker web service.

**Required env vars:**

| Key | Value |
|---|---|
| `JWT_SECRET` | Long random string |
| `MONEY_MANAGER_FRONTEND_URL` | `https://finance-tracker-28.netlify.app` |
| `APP_ACTIVATION_URL` | `https://finance-tracker-4lpe.onrender.com/` |

**Google OAuth (optional):**

| Key | Value |
|---|---|
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_ID` | (from Google Cloud Console) |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_SECRET` | (from Google Cloud Console) |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_SCOPE` | `email,profile` |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_REDIRECT_URI` | `https://finance-tracker-4lpe.onrender.com/login/oauth2/code/google` |

### Google Cloud Console setup
- **Authorized JavaScript origins:** `https://finance-tracker-28.netlify.app`, `https://finance-tracker-4lpe.onrender.com`
- **Authorized redirect URIs:** `https://finance-tracker-4lpe.onrender.com/login/oauth2/code/google`

---

## 🧪 Default Categories

On every new signup (email or Google), the following are auto‑seeded:

**Income (5):** Salary 💼, Freelance 💻, Business 🏢, Investments 📈, Gifts 🎁
**Expense (10):** Food & Dining 🍽️, Transport 🚗, Housing 🏠, Utilities 💡, Entertainment 🎬, Healthcare 🏥, Shopping 🛒, Education 🎓, Travel ✈️, Other 📌

---

## 🔨 Build & Test

```bash
./mvnw clean package           # build JAR
./mvnw test                    # run tests
java -jar target/moneymanager-0.0.1-SNAPSHOT.jar
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit: `git commit -m "feat: add my feature"`
4. Push & open a PR

---

## 📄 License

MIT © Roshan Prakhar

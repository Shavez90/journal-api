

# Journal API

A secure backend application for managing users and their personal journal entries.
Built with **Spring Boot**, **MongoDB**, and **JWT-based authentication**, following a clean, layered architecture.

This project focuses on **real-world backend practices**: stateless authentication, ownership enforcement, DTO usage, service-layer business logic, and environment-based configuration.

---

## Tech Stack

* Java 17
* Spring Boot
* Spring Security (JWT, BCrypt)
* Spring Web
* Spring Data MongoDB
* Maven
* MongoDB (Atlas / Local)

---

## Core Features

* User registration and authentication (JWT-based)
* Secure login with stateless JWT tokens
* Journal CRUD operations (Create, Read, Update, Delete)
* One user can own multiple journals
* **Ownership-based access control**

  * Users can only access and modify their own journals
* Role-based authorization (`USER`, `ADMIN`)
* DTO-based request and response handling
* Global exception handling with proper HTTP status codes
* Clean separation of Controller, Service, and Repository layers
* Environment-based configuration for secrets (production-ready)

---

## Authentication & Security

* Stateless JWT authentication
* Passwords stored using BCrypt hashing
* JWT extracted and validated via a security filter
* Authenticated user resolved via `SecurityContext`
* No `userId` is ever accepted from client requests

---

## API Overview

### Authentication APIs

* `POST /api/auth/register` – Register a new user
* `POST /api/auth/login` – Login and receive JWT token

### Journal APIs (Protected)

* `POST /api/journals` – Create a journal (authenticated user)
* `GET /api/journals` – Get journals for authenticated user
* `PUT /api/journals/{journalId}` – Update own journal
* `DELETE /api/journals/{journalId}` – Delete own journal

---

## Data Model (High Level)

### User

* id
* username
* email
* password (hashed)
* role

### Journal

* id
* title
* content
* userId (ownership)
* createdAt
* updatedAt

A journal belongs to a user through the `userId` field.
Ownership is enforced **server-side** in the service layer.

---

## Architecture Overview

```
Request
  → JWT Filter
    → Controller
      → Service (business logic + ownership)
        → Repository
          → MongoDB
```

### Design Principles

* Controllers are thin (HTTP only)
* Services enforce business rules and ownership
* Repositories handle data access only
* Entities are never exposed directly
* DTOs define API contracts

---

## Configuration & Secrets

This project uses **environment variables** for sensitive configuration:

* `MONGODB_URI`
* `JWT_SECRET`
* `JWT_EXPIRATION`
* `APP_FRONTEND_URL`

Secrets are **never committed** to source control.

---

## How to Run Locally

1. Clone the repository
2. Ensure MongoDB is running (local or Atlas)
3. Set required environment variables
4. Run the Spring Boot application
5. Test APIs using Postman (Bearer token required)

---

## Deployment

This project is **deployment-ready**.

* Works with Render / Railway / Heroku
* Stateless authentication
* Externalized configuration
* No hardcoded secrets

---

## Notes

* This project demonstrates **production-grade backend structure**
* Focus is on correctness, security, and clean architecture
* A simpler **Task API** can be built using the same patterns to reinforce learning

---

### Status

✅ Complete
✅ Secure
✅ Clean architecture
✅ Ready for extension or deployment

---

# Journal API

A backend application for managing users and their personal journal entries.
Built with Spring Boot and MongoDB using a clean, layered architecture.

This project focuses on correct backend design practices such as DTO usage,
service-layer business logic, ownership checks, and global exception handling.

---

## Tech Stack

- Java 17
- Spring Boot
- Spring Web
- Spring Data MongoDB
- Maven
- MongoDB

---

## Features

- User creation with validation
- Journal CRUD operations (Create, Read, Update, Delete)
- One user can have multiple journals
- Ownership-based access control (users can only modify their own journals)
- DTO-based request and response handling
- Global exception handling with proper HTTP status codes
- Clean separation of Controller, Service, and Repository layers

---

## API Overview

### User APIs
- `POST /api/users` – Create a user
- `GET /api/users/{id}` – Get user by ID

### Journal APIs
- `POST /api/journals` – Create a journal
- `GET /api/journals` – Get journals for a user
- `PUT /api/journals/{journalId}` – Update a journal
- `DELETE /api/journals/{journalId}` – Delete a journal

*(Currently, userId is passed as a request parameter. This will be replaced with JWT-based authentication later.)*

---

## Data Model (High Level)

- **User**
    - id
    - username
    - email

- **Journal**
    - id
    - title
    - content
    - userId
    - createdAt
    - updatedAt

A journal belongs to a user through the `userId` field.

---

## How to Run Locally

1. Clone the repository
2. Make sure MongoDB is running locally
3. Update `application.properties` if required
4. Run the Spring Boot application
5. Test APIs using Postman

---

## Notes

- This project is designed to be extended with Spring Security and JWT authentication.
- Current focus is on backend fundamentals and clean architecture.

---

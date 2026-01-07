# Journal API

A REST API for managing personal journal entries with user authentication and persistent storage.

## Features

- User authentication (signup, login, logout)
- Create, read, update, and delete journal entries
- Persistent data storage
- RESTful API design

## Technologies

- Node.js
- Express.js
- MongoDB
- JWT (JSON Web Tokens)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Shavez90/journal-api.git
cd journal-api
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
PORT=5000
```

4. Start the server:
```bash
npm start
```

The API will be available at `http://localhost:5000`

## API Endpoints

### Authentication

#### POST /api/auth/signup
Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Response:**
- Status: 201 Created
- Body: User object with authentication token

#### POST /api/auth/login
Authenticate and receive a JWT token.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- Status: 200 OK
- Body: User object with authentication token

#### POST /api/auth/logout
Logout the current user (invalidate token).

**Response:**
- Status: 200 OK

### Journals

#### GET /api/journals
Retrieve all journal entries for the authenticated user.

**Authorization:** Required (Bearer token)

**Response:**
- Status: 200 OK
- Body: Array of journal entry objects

#### POST /api/journals
Create a new journal entry.

**Authorization:** Required (Bearer token)

**Request Body:**
```json
{
  "title": "string",
  "content": "string",
  "tags": ["string"]
}
```

**Response:**
- Status: 201 Created
- Body: Created journal entry object

#### GET /api/journals/{journalId}
Retrieve a specific journal entry by ID.

**Authorization:** Required (Bearer token)

**Parameters:**
- `journalId` (path parameter): The ID of the journal entry

**Response:**
- Status: 200 OK
- Body: Journal entry object

#### PUT /api/journals/{journalId}
Update a specific journal entry.

**Authorization:** Required (Bearer token)

**Parameters:**
- `journalId` (path parameter): The ID of the journal entry

**Request Body:**
```json
{
  "title": "string",
  "content": "string",
  "tags": ["string"]
}
```

**Response:**
- Status: 200 OK
- Body: Updated journal entry object

#### DELETE /api/journals/{journalId}
Delete a specific journal entry.

**Authorization:** Required (Bearer token)

**Parameters:**
- `journalId` (path parameter): The ID of the journal entry

**Response:**
- Status: 204 No Content

## Error Handling

The API returns appropriate HTTP status codes and error messages:

- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid authentication token
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Shavez90

## Support

For issues and questions, please open an issue on the GitHub repository.

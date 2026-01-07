# Journal API

## Overview
The Journal API is a REST API for managing personal journals and entries.

## Endpoints

### GET /api/journals
Retrieve all journals for the authenticated user.

**Response:**
```json
[
  {
    "id": "journal-1",
    "title": "My Journal",
    "description": "A collection of my thoughts",
    "createdAt": "2026-01-01T00:00:00Z"
  }
]
```

### GET /api/journals/{journalId}
Retrieve a specific journal by ID.

**Parameters:**
- `journalId` (path parameter, required): The unique identifier of the journal

**Response:**
```json
{
  "id": "journal-1",
  "title": "My Journal",
  "description": "A collection of my thoughts",
  "createdAt": "2026-01-01T00:00:00Z",
  "entries": []
}
```

**Error Responses:**
- `404 Not Found`: Journal with the specified ID does not exist
- `401 Unauthorized`: User is not authenticated

### POST /api/journals
Create a new journal.

**Request Body:**
```json
{
  "title": "New Journal",
  "description": "Description of the journal"
}
```

**Response:**
```json
{
  "id": "journal-2",
  "title": "New Journal",
  "description": "Description of the journal",
  "createdAt": "2026-01-07T04:52:52Z"
}
```

## Installation

```bash
npm install
```

## Running the API

```bash
npm start
```

The API will be available at `http://localhost:3000`

## Authentication

All endpoints require authentication via JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

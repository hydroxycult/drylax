# API Documentation

This document describes the HTTP API for Drylax.

## Base URL

The default base URL is `http://localhost:8080`. In production, this will be your domain with HTTPS.

## API Endpoints

### Create a Paste

**POST** `/pastes`

Creates a new paste with encrypted content.

**Request Headers:**
- `Content-Type: application/json`

**Request Body:**
```json
{
  "content": "Your text content here",
  "duration": "1h"
}
```

**Parameters:**
- `content` (string, required): The text content to store. Maximum size is determined by `MAX_PASTE_SIZE` configuration.
- `duration` (string, optional): How long before the paste expires. Must be one of the values in `TTL_PRESETS`. Default presets: `5m`, `1h`, `24h`, `168h` (7 days).

**Success Response (201 Created):**
```json
{
  "id": "abc123xyz",
  "deletion_token": "dt_aBcD1234567890eFgH",
  "expires_at": "2025-11-30T12:00:00Z"
}
```

**Response Fields:**
- `id`: Unique identifier for the paste. Use this to retrieve the paste.
- `deletion_token`: Secret token required to delete the paste. Keep this secure.
- `expires_at`: ISO 8601 timestamp when the paste will automatically expire.

**Error Responses:**

**400 Bad Request:**
```json
{
  "error": "content is required"
}
```
Possible errors:
- `content is required`: Request body missing content field
- `content too large`: Content exceeds `MAX_PASTE_SIZE`
- `invalid duration`: Duration not in allowed presets

**500 Internal Server Error:**
```json
{
  "error": "internal server error",
  "request_id": "req_abc123"
}
```
Server encountered an error. Check server logs using the `request_id`.

**Example Request:**
```bash
curl -X POST http://localhost:8080/pastes \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello, World!",
    "duration": "1h"
  }'
```

---

### Retrieve a Paste

**GET** `/pastes/{id}`

Retrieves an existing paste by its ID.

**URL Parameters:**
- `id` (required): The paste ID returned when creating the paste

**Success Response (200 OK):**
```json
{
  "id": "abc123xyz",
  "content": "Hello, World!",
  "created_at": "2025-11-29T11:00:00Z",
  "expires_at": "2025-11-29T12:00:00Z"
}
```

**Response Fields:**
- `id`: The paste identifier
- `content`: The decrypted paste content
- `created_at`: When the paste was created
- `expires_at`: When the paste will expire

**Error Responses:**

**404 Not Found:**
```json
{
  "error": "paste not found"
}
```
The paste doesn't exist, has expired, or was deleted.

**500 Internal Server Error:**
```json
{
  "error": "internal server error",
  "request_id": "req_abc123"
}
```
Server error (possibly KMS unavailable or database error).

**Example Request:**
```bash
curl http://localhost:8080/pastes/abc123xyz
```

---

### Delete a Paste

**DELETE** `/pastes/{id}`

Deletes a paste using the deletion token.

**URL Parameters:**
- `id` (required): The paste ID

**Request Headers:**
- `X-Deletion-Token` (required): The deletion token provided when creating the paste

**Success Response (200 OK):**
```json
{
  "message": "paste deleted successfully"
}
```

**Error Responses:**

**401 Unauthorized:**
```json
{
  "error": "unauthorized"
}
```
Possible reasons:
- Missing `X-Deletion-Token` header
- Invalid or expired deletion token
- Token doesn't match the paste

**404 Not Found:**
```json
{
  "error": "paste not found"
}
```
The paste doesn't exist or was already deleted.

**429 Too Many Requests:**
```json
{
  "error": "rate limit exceeded"
}
```
Too many deletion attempts. Wait before trying again.

**Example Request:**
```bash
curl -X DELETE http://localhost:8080/pastes/abc123xyz \
  -H "X-Deletion-Token: dt_aBcD1234567890eFgH"
```

---

## Rate Limiting

All endpoints are rate limited per IP address. Default limits:
- 60 requests per minute
- 10 request burst

Exceeding the rate limit returns:

**429 Too Many Requests:**
```json
{
  "error": "rate limit exceeded"
}
```

**Response Headers:**
- `X-RateLimit-Limit`: Maximum requests per minute
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets

**Example:**
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1701234567
```

---

## Error Handling

All error responses follow this format:

```json
{
  "error": "human-readable error message",
  "request_id": "unique-request-identifier"
}
```

The `request_id` is included for server errors (5xx) and can be used to find the error in server logs.

### Common HTTP Status Codes

- **200 OK**: Request succeeded
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request (check error message)
- **401 Unauthorized**: Authentication failed
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server encountered an error

---

## Security Considerations

### HTTPS

Always use HTTPS in production. HTTP transmits data in plain text, including deletion tokens.

### Deletion Tokens

- Deletion tokens are secrets. Anyone with a token can delete the paste.
- Tokens expire after `DELETION_TOKEN_EXPIRY` (default: 24 hours).
- Do not share deletion tokens in paste content or public channels.

### Content Encryption

- All paste content is encrypted at rest using AES-256-GCM.
- Encryption uses the configured KMS provider.
- Encryption keys are never transmitted in API responses.

### IP Privacy

- Client IP addresses are hashed before storage.
- Original IPs are not stored or logged.
- IP hashes are used only for rate limiting.

---

## Client Examples

### Python

```python
import requests
import json

# Create paste
response = requests.post(
    'http://localhost:8080/pastes',
    headers={'Content-Type': 'application/json'},
    json={
        'content': 'Hello from Python!',
        'duration': '1h'
    }
)

if response.status_code == 201:
    data = response.json()
    paste_id = data['id']
    deletion_token = data['deletion_token']
    print(f"Created paste: {paste_id}")
    print(f"Deletion token: {deletion_token}")
    
    # Retrieve paste
    get_response = requests.get(f'http://localhost:8080/pastes/{paste_id}')
    if get_response.status_code == 200:
        print(f"Content: {get_response.json()['content']}")
    
    # Delete paste
    delete_response = requests.delete(
        f'http://localhost:8080/pastes/{paste_id}',
        headers={'X-Deletion-Token': deletion_token}
    )
    print(f"Deleted: {delete_response.status_code == 200}")
```

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const baseURL = 'http://localhost:8080';

async function example() {
    // Create paste
    const createRes = await axios.post(`${baseURL}/pastes`, {
        content: 'Hello from JavaScript!',
        duration: '1h'
    });
    
    const { id, deletion_token } = createRes.data;
    console.log(`Created paste: ${id}`);
    
    // Retrieve paste
    const getRes = await axios.get(`${baseURL}/pastes/${id}`);
    console.log(`Content: ${getRes.data.content}`);
    
    // Delete paste
    await axios.delete(`${baseURL}/pastes/${id}`, {
        headers: { 'X-Deletion-Token': deletion_token }
    });
    console.log('Deleted successfully');
}

example().catch(console.error);
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type CreateRequest struct {
    Content  string `json:"content"`
    Duration string `json:"duration"`
}

type CreateResponse struct {
    ID            string `json:"id"`
    DeletionToken string `json:"deletion_token"`
    ExpiresAt     string `json:"expires_at"`
}

func main() {
    baseURL := "http://localhost:8080"
    
    // Create paste
    reqBody, _ := json.Marshal(CreateRequest{
        Content:  "Hello from Go!",
        Duration: "1h",
    })
    
    resp, err := http.Post(baseURL+"/pastes", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    var createResp CreateResponse
    json.NewDecoder(resp.Body).Decode(&createResp)
    fmt.Printf("Created paste: %s\n", createResp.ID)
    
    // Retrieve paste
    getResp, _ := http.Get(fmt.Sprintf("%s/pastes/%s", baseURL, createResp.ID))
    defer getResp.Body.Close()
    
    // Delete paste
    req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/pastes/%s", baseURL, createResp.ID), nil)
    req.Header.Set("X-Deletion-Token", createResp.DeletionToken)
    http.DefaultClient.Do(req)
    fmt.Println("Deleted successfully")
}
```

---

## Testing the API

### Using cURL

The examples above use cURL, which is available on most systems.

**Check if cURL is installed:**
```bash
curl --version
```

**Basic workflow:**
```bash
# 1. Create a paste
RESPONSE=$(curl -s -X POST http://localhost:8080/pastes \
  -H "Content-Type: application/json" \
  -d '{"content":"Test paste","duration":"1h"}')

# 2. Extract ID and token (requires jq)
ID=$(echo $RESPONSE | jq -r '.id')
TOKEN=$(echo $RESPONSE | jq -r '.deletion_token')

# 3. Retrieve the paste
curl http://localhost:8080/pastes/$ID

# 4. Delete the paste
curl -X DELETE http://localhost:8080/pastes/$ID \
  -H "X-Deletion-Token: $TOKEN"
```

### Using Postman

1. Download Postman from https://www.postman.com/downloads/
2. Create a new request
3. Set method to POST
4. Set URL to `http://localhost:8080/pastes`
5. Go to Headers tab, add `Content-Type: application/json`
6. Go to Body tab, select "raw" and "JSON", enter request body
7. Click Send

---

## Limitations

- Maximum paste size: Configured by `MAX_PASTE_SIZE` (default 10 MB)
- Maximum duration: Limited by `TTL_PRESETS` (default max 7 days)
- Rate limits: Per-IP, configured in `.env`
- Binary content: Supported, but must be base64-encoded in JSON

---

## Future API Versions

This is API version 1. Future versions may add:
- Password-protected pastes
- Syntax highlighting hints
- Custom expiration times
- Paste editing

Breaking changes will be introduced in new API versions (e.g., `/v2/pastes`).  

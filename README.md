# n8n to OpenAI Proxy

A FastAPI server that converts n8n's NDJSON streaming format to OpenAI-compatible Server-Sent Events (SSE) format, enabling seamless integration with Open WebUI and other OpenAI-compatible clients.

## Features

- **OpenAI-Compatible API**: Full compatibility with `/v1/chat/completions` endpoint
- **Streaming Support**: Converts n8n NDJSON streams to OpenAI SSE format
- **Non-Streaming Support**: Also handles regular completion requests
- **Error Handling**: Comprehensive error handling and logging
- **CORS Support**: Ready for web client integration
- **Health Checks**: Built-in health check and models endpoints

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure n8n Settings

Copy `.env.example` to `.env` and update with your actual values:

```bash
cp .env.example .env
# Edit .env with your actual n8n webhook URL and auth token
```

### 3. Run the Proxy

```bash
python proxy.py
```

The server will start on `http://localhost:8000`

### 4. Configure Open WebUI

Point Open WebUI to: `http://localhost:8000`

## API Endpoints

### Chat Completions
- **POST** `/v1/chat/completions` - OpenAI-compatible chat completions
- **GET** `/v1/models` - List available models
- **GET** `/` - Health check

### Example Request

```bash
curl -X POST "http://localhost:8000/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_API_KEY" \
  -d '{
    "model": "n8nMem",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ],
    "stream": true
  }'
```

## How It Works

1. **Receives OpenAI-format requests** from clients like Open WebUI
2. **Forwards requests to n8n** webhook with proper authentication
3. **Converts n8n NDJSON streaming** to OpenAI SSE format:
   - `{"type": "begin"}` → Initial chunk with role
   - `{"type": "item", "content": "..."}` → Content chunks
   - `{"type": "end"}` → Final chunk with `finish_reason: "stop"`
4. **Returns OpenAI-compatible responses** to the client

## n8n Format → OpenAI Format

### n8n NDJSON Input:
```
{"type": "begin"}
{"type": "item", "content": "Hello"}
{"type": "item", "content": " there!"}
{"type": "end"}
```

### OpenAI SSE Output:
```
data: {"id": "chatcmpl-123", "object": "chat.completion.chunk", "created": 1694268190, "model": "n8nMem", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": null}]}

data: {"id": "chatcmpl-123", "object": "chat.completion.chunk", "created": 1694268190, "model": "n8nMem", "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": null}]}

data: {"id": "chatcmpl-123", "object": "chat.completion.chunk", "created": 1694268190, "model": "n8nMem", "choices": [{"index": 0, "delta": {"content": " there!"}, "finish_reason": null}]}

data: {"id": "chatcmpl-123", "object": "chat.completion.chunk", "created": 1694268190, "model": "n8nMem", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}

data: [DONE]
```

## Configuration

### Environment Variables
Create a `.env` file from the example:

```bash
cp .env.example .env
```

Then edit `.env` with your actual values:
```bash
N8N_WEBHOOK_URL=https://your-n8n-instance.com/webhook/v1/chat/completions
N8N_AUTH_TOKEN=your-auth-token
PROXY_API_KEY=your-secure-api-key
REQUEST_TIMEOUT=120.0
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=60
DEBUG_MODE=false
SECURITY_HEADERS_ENABLED=true
```

### CORS Security
The `ALLOWED_ORIGINS` setting controls which websites can access your proxy from a browser:
- **Development**: `http://localhost:3000,http://localhost:8080`
- **Production**: `https://yourdomain.com,https://app.yourdomain.com`
- **Disable browser access**: Remove the `ALLOWED_ORIGINS` line entirely

### Rate Limiting
Protects against API abuse by limiting requests per IP address:
- `RATE_LIMIT_REQUESTS=60` - Maximum requests per minute per IP
- `RATE_LIMIT_WINDOW=60` - Time window in seconds (currently unused, defaults to per minute)
- **Production**: Consider lower limits like `30` requests per minute
- **Development**: Higher limits like `100` for testing

### Security Headers
Adds protective HTTP headers to prevent web-based attacks:
- `SECURITY_HEADERS_ENABLED=true` - **Production**: Enables all security headers
- `SECURITY_HEADERS_ENABLED=false` - **Development**: Disables if causing issues
- **Headers included**: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP, HSTS
- **Protects against**: Clickjacking, XSS, MIME sniffing, code injection

### Error Handling & Security
Controls information disclosure in error messages:
- `DEBUG_MODE=false` - **Production**: Hides detailed error information
- `DEBUG_MODE=true` - **Development only**: Shows detailed errors for debugging
- **Never enable debug mode in production** - exposes sensitive information

### Logging
The proxy includes comprehensive logging. Set log level in the script:

```python
logging.basicConfig(level=logging.INFO)  # or DEBUG for verbose output
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure n8n webhook is accessible
2. **Authentication Errors**: Verify `N8N_AUTH_TOKEN` is correct
3. **Timeout Issues**: Increase `REQUEST_TIMEOUT` for longer responses
4. **CORS Issues**: CORS is enabled by default for all origins

### Debug Mode

For detailed logging, change the log level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Docker Deployment

### Quick Start with Docker

1. **Build and run with docker-compose** (recommended):
   ```bash
   docker-compose up --build
   ```

2. **Or build and run manually**:
   ```bash
   # Build the image
   docker build -t n8n-openai-proxy .
   
   # Run the container
   docker run -p 8000:8000 --name n8n-proxy n8n-openai-proxy
   ```

### Environment Variables for Docker

Set your environment variables before running:

```bash
# Set your actual values
export N8N_WEBHOOK_URL="https://your-n8n-instance.com/webhook/v1/chat/completions"
export N8N_AUTH_TOKEN="your-auth-token"
export PROXY_API_KEY="your-secure-api-key"
export REQUEST_TIMEOUT="120.0"

# Run with environment variables
docker-compose up
```

### Open WebUI Integration with Docker

When running both the proxy and Open WebUI in Docker:

1. **Use host networking** or **docker-compose** with shared network
2. **Configure Open WebUI** to connect to:
   - URL: `http://host.docker.internal:8000/v1` (if Open WebUI is in Docker)
   - URL: `http://localhost:8000/v1` (if Open WebUI is on host)
   - API Key: Use the value from `PROXY_API_KEY`
   - Model: `n8nMem`

### Docker Health Checks

The container includes health checks that verify the proxy is responding:
- Check interval: 30 seconds
- Timeout: 10 seconds
- Retries: 3

## Production Deployment

For production use:

1. **Docker (Recommended)**:
   ```bash
   docker-compose up -d --build
   ```

2. **Traditional ASGI server**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker proxy:app
   ```

3. Set up reverse proxy with nginx
4. Use environment variables for configuration
5. Implement proper authentication if needed

## License

MIT License - feel free to modify and use as needed.

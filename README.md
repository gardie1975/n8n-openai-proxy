# n8n to OpenAI Proxy

A FastAPI server that converts n8n's NDJSON streaming format to OpenAI-compatible Server-Sent Events (SSE) format, enabling seamless integration with Open WebUI and other OpenAI-compatible clients. Still a work in progress. The n8n webhook needs to be set as streamable and being only new, I am still working on the workflow which I will share in the future.

## Features

- **OpenAI-Compatible API**: Full compatibility with `/v1/chat/completions` endpoint
- **Streaming Support**: Converts n8n NDJSON streams to OpenAI SSE format
- **Non-Streaming Support**: Also handles regular completion requests
- **Security First**: Timing-attack resistant authentication, mandatory configuration validation
- **Error Handling**: Comprehensive error handling and logging
- **CORS Support**: Ready for web client integration with configurable origins
- **Rate Limiting**: Built-in rate limiting per IP address
- **Health Checks**: Built-in health check and models endpoints

## Recent Security Updates

⚠️ **Breaking Changes in Latest Version**:

This version includes critical security improvements that require configuration changes:

1. **Required Environment Variables**: `N8N_WEBHOOK_URL`, `N8N_AUTH_TOKEN`, and `PROXY_API_KEY` are now **mandatory**. The application will fail to start with a clear error message if any are missing. This prevents accidental deployment with insecure default credentials.

2. **Timing-Attack Protection**: API key validation now uses constant-time comparison to prevent timing-based attacks.

3. **CORS Policy Fix**: Removed hardcoded CORS wildcard that bypassed `ALLOWED_ORIGINS` configuration in streaming responses.

4. **Docker Healthcheck Fix**: Updated to use standard library instead of non-existent dependencies.

**Migration**: If upgrading from a previous version, ensure all three required environment variables are set in your `.env` file or environment before starting the application.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Required Settings ⚠️

**IMPORTANT**: The following environment variables are **REQUIRED**. The application will fail to start if any are missing.

Copy `.env.example` to `.env` and configure with your actual values:

```bash
cp .env.example .env
# Edit .env with your actual values - ALL required fields must be set
```

**Required Variables** (app will not start without these):
- `N8N_WEBHOOK_URL` - Your n8n webhook endpoint
- `N8N_AUTH_TOKEN` - Authentication token for n8n
- `PROXY_API_KEY` - Secure API key for proxy authentication

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

⚠️ **BREAKING CHANGE**: As of the latest version, security-critical environment variables are **REQUIRED** and have no default values. The application will fail to start with a clear error message if any required variable is missing.

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Then edit `.env` with your actual values:

#### **Required Variables** (application will not start without these)
```bash
N8N_WEBHOOK_URL=https://your-n8n-instance.com/webhook/v1/chat/completions
N8N_AUTH_TOKEN=your-secure-n8n-auth-token-here
PROXY_API_KEY=your-secure-proxy-api-key-here
```

**Security Note**: Generate strong, random values for `N8N_AUTH_TOKEN` and `PROXY_API_KEY`. Never use example values in production.

#### **Optional Variables** (with defaults)
```bash
REQUEST_TIMEOUT=120.0                    # Request timeout in seconds
ALLOWED_ORIGINS=http://localhost:3000   # Comma-separated CORS origins
RATE_LIMIT_REQUESTS=60                  # Max requests per minute per IP
RATE_LIMIT_WINDOW=60                    # Rate limit window (currently unused)
DEBUG_MODE=false                         # Show detailed errors (dev only)
SECURITY_HEADERS_ENABLED=true           # Enable security headers
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

## Security Features

This proxy implements several security best practices:

1. **Timing-Attack Resistant Authentication**: Uses constant-time comparison (`secrets.compare_digest()`) for API key validation to prevent timing-based attacks
2. **Mandatory Configuration**: Critical security credentials must be explicitly configured - no insecure defaults
3. **CORS Policy Enforcement**: Properly enforces configured `ALLOWED_ORIGINS` across all endpoints including streaming
4. **Rate Limiting**: Per-IP rate limiting to prevent abuse
5. **Security Headers**: Comprehensive HTTP security headers (CSP, X-Frame-Options, HSTS, etc.)
6. **Input Validation**: Request validation and sanitization
7. **Error Handling**: Prevents information disclosure in production mode

### Logging
The proxy includes comprehensive logging. Set log level in the script:

```python
logging.basicConfig(level=logging.INFO)  # or DEBUG for verbose output
```

## Troubleshooting

### Common Issues

1. **Application Won't Start - "environment variable is required"**:
   - **Cause**: Missing required environment variables
   - **Solution**: Ensure `.env` file exists with all three required variables: `N8N_WEBHOOK_URL`, `N8N_AUTH_TOKEN`, and `PROXY_API_KEY`
   - Example error: `ValueError: PROXY_API_KEY environment variable is required`

2. **Connection Refused**:
   - Ensure n8n webhook is accessible from the proxy server
   - Verify `N8N_WEBHOOK_URL` is correct and reachable

3. **401 Authentication Errors**:
   - Verify `N8N_AUTH_TOKEN` matches your n8n webhook configuration
   - Ensure clients are using the correct `PROXY_API_KEY` in the Authorization header

4. **Timeout Issues**:
   - Increase `REQUEST_TIMEOUT` for longer responses
   - Default is 120 seconds

5. **CORS Issues**:
   - Configure `ALLOWED_ORIGINS` with your client's domain
   - For development, use `http://localhost:3000` or your dev server port
   - For production, use your actual domain (never use `*` in production)

6. **Docker Container Exits Immediately**:
   - Check logs: `docker logs n8n-openai-proxy-test`
   - Most common cause: Missing required environment variables
   - Ensure all required variables are set in docker-compose.yml or exported before running

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

⚠️ **REQUIRED**: Set these environment variables before running, or the container will fail to start:

```bash
# Set your actual values (REQUIRED - container will exit if not set)
export N8N_WEBHOOK_URL="https://your-n8n-instance.com/webhook/v1/chat/completions"
export N8N_AUTH_TOKEN="your-secure-n8n-auth-token"
export PROXY_API_KEY="your-secure-proxy-api-key"

# Optional variables (with defaults)
export REQUEST_TIMEOUT="120.0"
export ALLOWED_ORIGINS="http://localhost:3000,http://localhost:8080"
export RATE_LIMIT_REQUESTS="60"
export DEBUG_MODE="false"
export SECURITY_HEADERS_ENABLED="true"

# Run with environment variables
docker-compose up
```

**Alternative**: Create a `.env` file in the same directory as `docker-compose.yml` with the required variables. Docker Compose will automatically load it.

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

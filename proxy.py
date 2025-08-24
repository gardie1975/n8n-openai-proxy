from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import json
import time
import uuid
import logging
import os
from typing import AsyncGenerator, Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "https://n8n/v1/chat/completions")
N8N_AUTH_TOKEN = os.getenv("N8N_AUTH_TOKEN", "123456")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "120.0"))

# API Key for proxy authentication
PROXY_API_KEY = os.getenv("PROXY_API_KEY", "sk-proxy-n8n-fastapi-2024-secure-key-abc123def456")

# CORS Origins - Parse comma-separated list
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Debug mode configuration
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# Security headers configuration
SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "true").lower() == "true"

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="n8n to OpenAI Proxy",
    description="Converts n8n NDJSON streaming to OpenAI-compatible SSE format",
    version="1.0.0"
)

# Set up rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Only add security headers if enabled
    if SECURITY_HEADERS_ENABLED:
        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME sniffing attacks
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Force HTTPS in production (only add if HTTPS is detected)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Content Security Policy - restrict resource loading
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        
        # Additional security headers
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response

# Add CORS middleware for web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"status": "healthy", "service": "n8n-openai-proxy"}

@app.get("/v1/models")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/minute")
async def list_models(request: Request):
    """OpenAI-compatible models endpoint"""
    return {
        "object": "list",
        "data": [
            {
                "id": "n8nMem",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "n8n-proxy"
            }
        ]
    }

@app.post("/v1/chat/completions")
@limiter.limit(f"{RATE_LIMIT_REQUESTS}/minute")
async def chat_completions(request: Request):
    """Main chat completions endpoint - OpenAI compatible"""
    try:
        # API key validation
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Missing authorization header")
        
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header format")
        
        token = auth_header.replace("Bearer ", "")
        if token != PROXY_API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        body = await request.json()
        logger.info(f"Received request for model: {body.get('model', 'n8nMem')}")
        
        # Validate required fields
        if "messages" not in body:
            raise HTTPException(status_code=400, detail="Missing required field: messages")
        
        # Check if streaming is requested
        if body.get("stream", False):
            logger.info("Streaming response requested")
            return StreamingResponse(
                stream_n8n_response(body), 
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Content-Type": "text/event-stream; charset=utf-8",
                    "Access-Control-Allow-Origin": "*"
                }
            )
        else:
            logger.info("Non-streaming response requested")
            return await get_complete_n8n_response(body)
            
    except json.JSONDecodeError:
        logger.warning("Invalid JSON received in request body")
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")
    except HTTPException:
        # Re-raise HTTP exceptions (auth errors, etc.)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in chat_completions: {str(e)}")
        if DEBUG_MODE:
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
        else:
            raise HTTPException(status_code=500, detail="Internal server error")

async def stream_n8n_response(openai_request: Dict[str, Any]) -> AsyncGenerator[str, None]:
    """Convert n8n NDJSON streaming to OpenAI SSE format"""
    
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:29]}"
    created_time = int(time.time())
    model = openai_request.get("model", "n8nMem")
    
    headers = {
        "Authorization": f"Bearer {N8N_AUTH_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/x-ndjson"
    }
    
    logger.info(f"Starting stream for completion_id: {completion_id}")
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            async with client.stream(
                'POST', 
                N8N_WEBHOOK_URL,
                json=openai_request,
                headers=headers
            ) as response:
                
                logger.info(f"n8n response status: {response.status_code}")
                
                if response.status_code != 200:
                    error_text = await response.aread() if hasattr(response, 'aread') else b"Unknown error"
                    logger.error(f"Backend service error {response.status_code}: {error_text}")
                    
                    error_chunk = create_openai_chunk(
                        completion_id, created_time, model, 0,
                        content="Service temporarily unavailable",
                        finish_reason="stop"
                    )
                    yield f"data: {json.dumps(error_chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                
                # Send initial chunk with role
                initial_chunk = create_openai_chunk(
                    completion_id, created_time, model, 0,
                    role="assistant", content=""
                )
                yield f"data: {json.dumps(initial_chunk)}\n\n"
                
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                        
                    try:
                        chunk_data = json.loads(line)
                        logger.debug(f"Received chunk: {chunk_data.get('type', 'unknown')}")
                        
                        # Handle different n8n chunk types
                        if chunk_data.get("type") == "begin":
                            logger.info("Stream began")
                            continue
                            
                        elif chunk_data.get("type") == "item" and "content" in chunk_data:
                            content_chunk = create_openai_chunk(
                                completion_id, created_time, model, 0,
                                content=chunk_data["content"]
                            )
                            yield f"data: {json.dumps(content_chunk)}\n\n"
                        
                        elif chunk_data.get("type") == "end":
                            logger.info("Stream ended")
                            final_chunk = create_openai_chunk(
                                completion_id, created_time, model, 0,
                                finish_reason="stop"
                            )
                            yield f"data: {json.dumps(final_chunk)}\n\n"
                            yield "data: [DONE]\n\n"
                            return
                            
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse n8n chunk: {line[:100]}... Error: {e}")
                        continue
                        
    except httpx.TimeoutException:
        logger.error("Request to backend service timed out")
        error_chunk = create_openai_chunk(
            completion_id, created_time, model, 0,
            content="Request timed out",
            finish_reason="stop"
        )
        yield f"data: {json.dumps(error_chunk)}\n\n"
        yield "data: [DONE]\n\n"
        
    except Exception as e:
        logger.error(f"Streaming error: {str(e)}")
        error_chunk = create_openai_chunk(
            completion_id, created_time, model, 0,
            content="Service temporarily unavailable",
            finish_reason="stop"
        )
        yield f"data: {json.dumps(error_chunk)}\n\n"
        yield "data: [DONE]\n\n"

async def get_complete_n8n_response(openai_request: Dict[str, Any]) -> Dict[str, Any]:
    """Non-streaming response - collect all chunks"""
    
    # Force non-streaming for n8n request
    request_copy = openai_request.copy()
    request_copy["stream"] = False
    
    headers = {
        "Authorization": f"Bearer {N8N_AUTH_TOKEN}",
        "Content-Type": "application/json"
    }
    
    completion_id = f"chatcmpl-{uuid.uuid4().hex[:29]}"
    created_time = int(time.time())
    model = openai_request.get("model", "n8nMem")
    
    logger.info(f"Starting non-streaming request for completion_id: {completion_id}")
    
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(
                N8N_WEBHOOK_URL,
                json=request_copy,
                headers=headers
            )
            
            logger.info(f"n8n response status: {response.status_code}")
            
            if response.status_code != 200:
                logger.error(f"Backend service error: {response.status_code}")
                raise HTTPException(
                    status_code=502, 
                    detail="Service temporarily unavailable"
                )
            
            # Collect all content from n8n chunks
            full_content = ""
            for line in response.text.split('\n'):
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    if chunk.get("type") == "item" and "content" in chunk:
                        full_content += chunk["content"]
                except json.JSONDecodeError:
                    continue
            
            # Calculate token usage (rough estimation)
            prompt_tokens = estimate_tokens(str(openai_request.get("messages", "")))
            completion_tokens = estimate_tokens(full_content)
            
            return {
                "id": completion_id,
                "object": "chat.completion",
                "created": created_time,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": full_content
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens
                }
            }
            
    except httpx.TimeoutException:
        logger.error("Request to backend service timed out")
        raise HTTPException(status_code=504, detail="Request timed out")
    except Exception as e:
        logger.error(f"Non-streaming error: {str(e)}")
        if DEBUG_MODE:
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
        else:
            raise HTTPException(status_code=500, detail="Internal server error")

def create_openai_chunk(
    completion_id: str, 
    created_time: int, 
    model: str, 
    index: int,
    role: str = None,
    content: str = None,
    finish_reason: str = None
) -> Dict[str, Any]:
    """Create OpenAI-compatible streaming chunk"""
    delta = {}
    if role:
        delta["role"] = role
    if content:
        delta["content"] = content
    
    return {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created_time,
        "model": model,
        "choices": [{
            "index": index,
            "delta": delta,
            "finish_reason": finish_reason
        }]
    }

def estimate_tokens(text: str) -> int:
    """Rough token estimation (4 chars ≈ 1 token)"""
    return max(1, len(text) // 4)

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting n8n to OpenAI proxy server...")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )

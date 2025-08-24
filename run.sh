#!/bin/bash

# FastAPI OpenAI Proxy - Virtual Environment Runner
# This script activates the virtual environment and runs the proxy server

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Starting FastAPI OpenAI Proxy server..."
python proxy.py

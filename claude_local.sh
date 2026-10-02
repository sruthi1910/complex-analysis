#!/bin/bash
ANTHROPIC_BASE_URL="http://localhost:8888" \
ANTHROPIC_AUTH_TOKEN="sk-litellm-dev-key" \
ANTHROPIC_DEFAULT_HAIKU_MODEL="llama3.1" \
MAX_THINKING_TOKENS="0" \
claude --model llama3.1 "$@"

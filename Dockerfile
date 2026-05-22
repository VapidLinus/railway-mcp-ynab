FROM python:3.12-slim

# Install Node.js (needed for supergateway)
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

# Install mcp-ynab
RUN pip install mcp-ynab==1.0.1

# Install supergateway (bridges stdio -> HTTP/SSE)
RUN npm install -g supergateway

EXPOSE 8000

CMD supergateway --stdio "mcp-ynab" --port ${PORT:-8000} --oauth2Bearer ${MCP_AUTH_TOKEN}

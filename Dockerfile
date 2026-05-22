FROM python:3.13-slim

# Install Node.js (needed for supergateway) and git (needed for pip install from GitHub)
RUN apt-get update && apt-get install -y nodejs npm git && rm -rf /var/lib/apt/lists/*

# Install mcp-ynab from GitHub
RUN pip install git+https://github.com/pragprogrammer/mcp-ynab.git

# Install supergateway (bridges stdio -> HTTP/SSE)
RUN npm install -g supergateway

EXPOSE 8000

CMD supergateway --stdio "mcp-ynab" --port ${PORT:-8000} --oauth2Bearer ${MCP_AUTH_TOKEN}

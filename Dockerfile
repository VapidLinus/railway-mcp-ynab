FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uvicorn "git+https://github.com/pragprogrammer/mcp-ynab.git"

WORKDIR /app
COPY serve.py .

EXPOSE 8080
CMD ["python", "serve.py"]

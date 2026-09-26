# CanaryMesh - Honeytoken-as-a-Service Container Image
FROM python:3.11-slim

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and scripts
COPY app/ ./app/
COPY cli/ ./cli/
COPY scripts/ ./scripts/
COPY pyproject.toml README.md ./

# Install CLI locally in container
RUN pip install --no-cache-dir -e .

# Expose HTTP port
EXPOSE 8000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV CANARY_HOST=0.0.0.0
ENV CANARY_PORT=8000
ENV CANARY_DATABASE_PATH=/app/data/canarymesh.db

# Ensure data directory exists for persistent SQLite database
RUN mkdir -p /app/data

# Run with Uvicorn
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

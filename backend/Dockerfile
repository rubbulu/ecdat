FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (git for repo cloning, build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application code, data catalogue, and sample targets
COPY backend /app/backend
COPY sample_targets /app/sample_targets
COPY docs /app/docs

ENV PYTHONPATH=/app
ENV PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

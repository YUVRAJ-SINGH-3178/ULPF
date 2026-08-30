# ==============================================================================
# ULPF — Universal Log Pre-processing Framework
# Air-Gapped Container Image (NTRO SIH26156)
# ==============================================================================

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ULPF_AIR_GAPPED=1 \
    PORT=8000

WORKDIR /app

# Install build tools if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and sample data
COPY ulpf/ ./ulpf/
COPY sample_data/ ./sample_data/
COPY run_ulpf.py .

# Create persistent data directories
RUN mkdir -p data/raw_store data/parsers data/onboarding_sessions data/error_queue data/data_lake

# Security: non-root user
RUN useradd -m -u 1000 ulpfuser && chown -R ulpfuser:ulpfuser /app
USER ulpfuser

EXPOSE 8000 5140/udp 1514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/pipeline/health || exit 1

CMD ["python", "run_ulpf.py"]

# Matches the local Python version so the pickled models load identically.
FROM python:3.10-slim

WORKDIR /app

# Dependencies first, so code edits do not invalidate the install layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY models/live_detector.joblib models/live_classifier.joblib ./models/
COPY demo/ ./demo/

# A container has no meaningful network interface to watch, so live capture
# is off here. The API returns a clear 503 instead of a permission error.
ENV ALLOW_LIVE_CAPTURE=0 \
    PYTHONUNBUFFERED=1

# Do not run the web process as root.
RUN useradd --create-home --shell /bin/false guardian && chown -R guardian:guardian /app
USER guardian

EXPOSE 8000

# Hosts such as Render inject $PORT; fall back to 8000 locally.
CMD ["sh", "-c", "uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY models/live_detector.joblib models/live_classifier.joblib ./models/
COPY demo/ ./demo/

ENV ALLOW_LIVE_CAPTURE=0 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /bin/false guardian && chown -R guardian:guardian /app
USER guardian

EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

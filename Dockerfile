FROM python:3.12-slim

WORKDIR /app

# Yukti (the governor) and its dependencies, pulled from the public repo.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ailab ./ailab
COPY demo.py .

ENV PYTHONPATH=/app

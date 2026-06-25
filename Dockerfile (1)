FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY vulnapp.py .

# Data directory for SQLite DB
RUN mkdir -p /app/data
ENV VULNAPP_DB=/app/data/vulnapp.db
ENV VULNAPP_PORT=5000

EXPOSE 5000

CMD ["python", "vulnapp.py"]

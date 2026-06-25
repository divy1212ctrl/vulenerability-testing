FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all scanner modules
COPY main.py .
COPY sqli_scanner.py .
COPY xss_scanner.py .
COPY header_analyzer.py .
COPY report_generator.py .
COPY api_server.py .

# Reports output directory
RUN mkdir -p /app/reports

EXPOSE 8000

CMD ["python", "api_server.py", "--port", "8000", "--results-dir", "/app/reports"]

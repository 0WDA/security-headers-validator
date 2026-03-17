FROM python:3.11-slim

WORKDIR /app

COPY security_headers_validator.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "security_headers_validator.py"]
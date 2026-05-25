# Specify the Python 3.10 version as requested by the team
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY . .

# Default command to run the application
CMD ["python", "main.py"]
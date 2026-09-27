# Use an official Python runtime as a parent image
FROM python:3.11-slim AS runner

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /app

# Install system dependencies (if needed, e.g., for compiled Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script(s) into the container
COPY scripts/ /app/scripts/

# Default command: run the script passed as argument
ENTRYPOINT ["python", "/app/scripts/main.py"]
#CMD ["main.py"]

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies if any are needed for boto3/cryptography
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and requirements
COPY pyproject.toml requirements.txt ./

# Upgrade pip and install the project
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Copy the rest of the application
COPY . .

# Create a non-root user
RUN useradd -m auditor
USER auditor

# Provide a standard entrypoint
ENTRYPOINT ["aws-audit"]
CMD ["--help"]

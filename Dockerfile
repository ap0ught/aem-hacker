FROM python:3.12-slim

# Install OS updates to pick up any security fixes in the base image.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /aem-hacker

# Install dependencies first (better layer caching).
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy application source.  .dockerignore excludes .git, caches, venvs, etc.
COPY . .

ENTRYPOINT [ "/bin/bash" ]


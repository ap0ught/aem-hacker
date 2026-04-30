FROM python:3.12-slim

# Install OS updates to pick up any security fixes in the base image.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /aem-hacker

# Copy local source so the image uses the code from this repository
# rather than a potentially stale remote clone.
COPY . .

RUN python -m pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "/bin/bash" ]


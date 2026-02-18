FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    git nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# clone server repo
RUN git clone https://github.com/GOMPLY-RBI/nmap-mcpserver.git

WORKDIR /app/nmap-mcpserver

# Install server dependencies
RUN pip install --no-cache-dir -r requirements.txt

# expose port
EXPOSE 3001

CMD ["python", "-m", "src.nmap_mcp"] 

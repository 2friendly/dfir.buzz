# Use a lightweight Node.js image
FROM node:18-slim

# Set working directory
WORKDIR /app

# Install dependencies, the correct whois package, and Subfinder
RUN apt-get update && apt-get install -y --no-install-recommends ntp wget unzip ca-certificates whois && \
    update-ca-certificates && \
    wget --progress=dot:giga -O subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_amd64.zip" && \
    unzip subfinder.zip && \
    mv subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf subfinder.zip

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy the rest of the application
COPY . .

# Expose the correct port for Cloud Run
EXPOSE 8080

# Start the Node.js server
CMD ["node", "server.js"]

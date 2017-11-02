FROM python:3.6
MAINTAINER Bart Jeukendrup <bart@jeukendrup.nl>

# Install OS dependencies
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash - && \
    apt-get install -y nodejs

# Install app dependencies
RUN mkdir /app
WORKDIR /app
ADD requirements.txt /app
ADD package.json /app
ADD package-lock.json /app

RUN pip install -r requirements.txt
RUN npm install

# Add app
ADD . /app

# Build the frontend
RUN npm run build

# Boot script
ADD docker/config.py /app/pleio_account/config.py
ADD docker/start.sh /start.sh
RUN chmod +x /start.sh

# Cleanup all the build packages
RUN apt-get remove -y nodejs
RUN rm -rf node_modules && rm -rf /var/lib/apt/lists/*

# HTTP port
EXPOSE 8000

# Define run script
CMD ["/start.sh"]

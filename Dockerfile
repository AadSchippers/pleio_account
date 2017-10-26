FROM python:3.6
MAINTAINER Bart Jeukendrup <bart@jeukendrup.nl>

# Install app dependencies
RUN mkdir /app
WORKDIR /app
ADD requirements.txt /app
RUN pip install -r requirements.txt

# Add app
ADD . /app

# HTTP port
EXPOSE 8000

# Define run script
CMD ["python manage.py runserver 0.0.0.0:8000"]

FROM python:3.10-alpine

WORKDIR /app
ADD . /app
EXPOSE 8080
CMD [ "python", "wowhoneypot.py" ]
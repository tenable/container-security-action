FROM python:3.13.0a3-slim AS builder
ADD . /app
WORKDIR /app

# We are installing a dependency here directly into our app source dir
RUN pip install --target=/app -r requirements.txt

WORKDIR /app
ENV PYTHONPATH /app
RUN chmod +x /app/src/main/main.py
CMD ["/app/src/main/main.py"]

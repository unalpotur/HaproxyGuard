FROM python:3.12-slim

WORKDIR /srv

# haproxy binary enables real `haproxy -c` validation (auto-fix, cluster deploy).
RUN apt-get update \
 && apt-get install -y --no-install-recommends haproxy openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

# Install the package and its dependencies.
COPY backend/pyproject.toml ./
COPY backend/app ./app
COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
RUN pip install --no-cache-dir .

EXPOSE 8000

# Run migrations then start the server.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM python:3.12-slim

WORKDIR /srv

# haproxy binary enables real `haproxy -c` validation (auto-fix, cluster deploy).
RUN apt-get update \
 && apt-get install -y --no-install-recommends haproxy \
 && rm -rf /var/lib/apt/lists/*

# Install the package and its dependencies (fastapi, uvicorn, pydantic,
# cryptography, …) from pyproject so the image matches the code.
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

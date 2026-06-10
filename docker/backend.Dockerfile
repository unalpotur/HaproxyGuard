FROM python:3.12-slim

WORKDIR /srv
COPY backend/pyproject.toml ./
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic

COPY backend/app ./app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

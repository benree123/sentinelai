FROM node:22-alpine AS frontend
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app/ ./app/
COPY --from=frontend /web/dist /app/frontend/dist
RUN useradd --create-home sentinel && mkdir data && chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 5090
HEALTHCHECK --interval=5s --timeout=4s --start-period=20s --retries=12 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5090/api/health', timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5090"]

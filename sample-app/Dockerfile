FROM python:3.13.7-slim

RUN groupadd --system app && useradd --system --gid app --create-home app
WORKDIR /app
COPY --chown=app:app app.py /app/app.py
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["python", "/app/app.py"]

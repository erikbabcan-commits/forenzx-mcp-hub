FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd -r forenzx && useradd -r -g forenzx -d /app forenzx
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip && pip install \
    "fastapi>=0.110,<1" "uvicorn[standard]>=0.28,<1" "pydantic>=2.6,<3" \
    "pydantic-settings>=2.2,<3" "docker>=7,<8" "httpx>=0.27,<1" "jsonschema>=4.21,<5" \
    "pyyaml>=6,<7" "cryptography>=42,<47" "PyJWT>=2.9,<3" "passlib[bcrypt]>=1.7,<2" \
    "jinja2>=3.1,<4" "python-multipart>=0.0.9,<1" \
    "pytz" "pillow" "simplekml" "xmltodict" "xlsxwriter" "pycryptodome" "pycryptodomex" \
    "bencoding" "beautifulsoup4" "fitdecode" "folium" "polyline" "protobuf>=5.29.6" \
    "pandas" "biplist" "ijson" "mmh3" "python-dateutil" "nska-deserialize" "pyasn1"
COPY core ./core
COPY packs ./packs
COPY workers ./workers
COPY scripts ./scripts
RUN mkdir -p /data/backups /tmp/forenzx_scratch /app/reports && chown -R forenzx:forenzx /app /data /tmp/forenzx_scratch /app/reports
USER forenzx
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"
CMD ["uvicorn","core.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]

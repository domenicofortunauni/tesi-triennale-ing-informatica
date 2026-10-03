FROM python:3.12-slim

WORKDIR /app

# PyMySQL e' puro Python: nessuna libreria di sistema da compilare.
RUN pip install --no-cache-dir flask==3.1.* pymysql==1.1.*

COPY app.py .
COPY templates/ templates/
COPY static/ static/

EXPOSE 5000
CMD ["python", "app.py"]

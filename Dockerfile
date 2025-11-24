FROM registry.lil.tools/library/python:3.11-bookworm
ENV PYTHONUNBUFFERED=1
ENV UVICORN_PORT=8000

# install clamav
# https://www.clamav.net/documents/installing-clamav#debian
ARG clamav-cache-buster
RUN apt-get update \
    && apt-get install -y clamav clamav-daemon

RUN freshclam

# pip
RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app
RUN pip install pip==24.0  \
    && pip install -r requirements.txt --src /usr/local/src \
    && rm requirements.txt

COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/bin/bash", "-c", "uvicorn main:app --host=0.0.0.0 --port=${UVICORN_PORT}"]

COPY main.py /app/main.py
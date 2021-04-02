FROM python:3.6.1-alpine

COPY prosafe_exporter/requirements.txt /tmp/

RUN apk add --no-cache --virtual .build-deps gcc libc-dev libxslt-dev && \
    apk add --no-cache libxslt && \
    pip install -r /tmp/requirements.txt && \
    apk del .build-deps

WORKDIR /prosafe_exporter
COPY /prosafe_exporter/prosafe_exporter.py .

CMD ["python","prosafe_exporter.py", "/etc/prosafe_exporter/config.yml"]

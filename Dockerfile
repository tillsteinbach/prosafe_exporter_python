FROM python:3.6.1-alpine

ENV CONFIG=/etc/prosafe_exporter/config.yml

COPY prosafe_exporter prosafe_exporter

RUN apk add --no-cache --virtual .build-deps gcc libc-dev libxml2-dev libxslt-dev && \
    apk add --no-cache libxslt && \
    pip install ./prosafe_exporter/ && \
    apk del .build-deps

CMD ["prosafe_exporter", "${CONFIG}"]

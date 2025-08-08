FROM python:3.12-alpine@sha256:ba13ef990f6e5d13014e9e8d04c02a8fdb0fe53d6dccf6e19147f316e6cc3a84

ENV USER chall

USER root
RUN apk add socat
RUN adduser -D -g "" -u 1337 $USER
RUN pip install pycryptodome

USER $USER
WORKDIR /app
COPY ./deploy/chal.py /app
COPY ./deploy/flag /app

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 -u chal.py,nofork,stderr"]
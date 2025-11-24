FROM python:3.11-alpine

RUN apk update \
    && apk add --no-cache \
    build-base \
    shadow \
    gcc \
    make \
    && rm -rf /var/cache/apk/*

COPY . /app
WORKDIR /app

RUN gcc /app/xor.c -o /app/xor \
    && chmod u+s /app/xor

RUN mv /app/flag.txt /flag \
    && chmod 600 /flag \
    && chown root:root /flag

RUN pip install --no-cache-dir flask

RUN adduser -D -s /bin/sh user

RUN echo "user:password" | chpasswd

RUN echo "user:x:1000:1000::/home/user:/bin/sh" > /etc/passwd \
    && echo "root:x:0:0:root:/root:/bin/sh" >> /etc/passwd

RUN chmod u+s /bin/su

EXPOSE 5000

USER user
CMD ["python", "app.py"]

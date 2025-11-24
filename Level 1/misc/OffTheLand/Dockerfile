FROM ubuntu:22.04

RUN apt update && apt install -y python3 socat

COPY ./flag.txt /flag
COPY ./init /init

RUN chmod +x /init

EXPOSE 5000
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/init,pty,stderr

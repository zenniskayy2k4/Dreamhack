FROM ubuntu:24.04

ENV USER rootsquare

USER root
RUN apt-get update
RUN apt-get -y install socat
RUN useradd -u 1337 -s /bin/bash -M $USER

WORKDIR /chall
COPY cuccoo .
COPY flag.txt .

RUN chown $USER:$USER /chall/cuccoo /chall/flag.txt
RUN chmod 0500 /chall/cuccoo
RUN chmod 0400 /chall/flag.txt

USER $USER
EXPOSE 5000

CMD ["socat","-T","25","TCP-LISTEN:5000,reuseaddr,fork","EXEC:./cuccoo"]
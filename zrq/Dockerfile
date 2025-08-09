FROM ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

WORKDIR /poka

COPY zrq ./zrq
COPY quiz ./quiz

RUN chmod +x zrq

CMD bash -c './zrq <<< quiz'

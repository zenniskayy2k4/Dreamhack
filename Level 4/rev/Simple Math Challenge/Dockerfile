FROM ubuntu:24.04@sha256:d4f6f70979d0758d7a6f81e34a61195677f4f4fa576eaf808b79f17499fd93d1

RUN apt-get update
RUN apt-get install -y gcc socat

RUN useradd gshs

ADD ./flag /home/gshs/flag
ADD ./chall /home/gshs/chall

RUN chown -R root:root /home/gshs
RUN chown root:gshs /home/gshs/flag
RUN chown root:gshs /home/gshs/chall

RUN chmod 755 /home/gshs/chall
RUN chmod 440 /home/gshs/flag

WORKDIR /home/gshs
USER gshs
EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./chall,nofork,stderr"]
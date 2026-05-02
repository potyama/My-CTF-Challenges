# NOTE: This hash is pinned to avoid version and environment differences.
FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15

RUN apt-get -y update --fix-missing && \
    apt-get -y install socat

WORKDIR /home/alpaca
COPY --chmod=555 chal .
COPY --chmod=444 flag.txt .
USER nobody:nogroup
CMD ["socat", "TCP-L:1337,fork,reuseaddr", "EXEC:./chal,stderr"]

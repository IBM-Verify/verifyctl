FROM registry.access.redhat.com/ubi9/ubi-micro

USER root

RUN mkdir .verify && \
    chown -R 1001 .verify

USER 1001

ENV GOTRACEBACK=crash \
    GODEBUG=x509ignoreCN=0

COPY bin/verifyctl /usr/bin

ENTRYPOINT ["/bin/verifyctl"]
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETOS
ARG TARGETARCH

COPY secretgenerator /usr/local/bin/secretgenerator

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/secretgenerator"]

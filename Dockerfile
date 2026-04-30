FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETOS
ARG TARGETARCH

COPY keygenerator /usr/local/bin/keygenerator

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/keygenerator"]

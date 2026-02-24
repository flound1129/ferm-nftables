FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    devscripts \
    dh-python \
    python3-all \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN chmod +x debian/rules && chmod +x debian/*.sh 2>/dev/null || true

CMD ["bash"]

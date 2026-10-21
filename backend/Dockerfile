# Multi-stage build for Spring Boot application
# Stage 1: Build the application
FROM maven:3.9-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Copy pom.xml and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Build nDPI for the target architecture. ntop's Ubuntu repository only publishes
# x86_64 packages, so installing `ndpi` from its x64/ repo fails on Apple Silicon.
# Use the same pinned release on ARM64 and AMD64 instead of silently losing DPI
# support or forcing the entire backend through x86 emulation.
FROM ubuntu:22.04 AS ndpi-build
WORKDIR /src/ndpi
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential autoconf automake libtool pkg-config \
        gettext flex bison libpcap-dev libjson-c-dev libpcre2-dev && \
    curl -fsSL --retry 3 https://codeload.github.com/ntop/nDPI/tar.gz/refs/tags/5.0 \
        -o /tmp/ndpi.tar.gz && \
    echo '8b0d3dc0c8a6a68578e09a18c922021ef6458d4aca1c7a20ce04efc267aa9ea5  /tmp/ndpi.tar.gz' \
        | sha256sum -c - && \
    tar -xzf /tmp/ndpi.tar.gz --strip-components=1 && \
    ./autogen.sh && ./configure --with-pcre2 && \
    make -j2 -C src/lib && make -j2 -C example && \
    install -Dm755 example/ndpiReader /out/ndpiReader && \
    printf '5.0.0 (source)\n' > /out/ndpi-version

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Install runtime dependencies:
#   tshark    — PCAP/pcapng parser
#   ndpi      — ndpiReader for application-layer DPI (native build above)
#   suricata  — offline IDS engine for signature-based threat detection (eve.json)
#   tzdata    — timezone data
#   gosu      — privilege-drop helper for entrypoint
#
# Ubuntu 22.04's built-in nDPI (4.2-2) lacks H.225/H.245 session tracking and
# several protocol signatures added in v5. The native source build preserves
# these on ARM64 too. To refresh nDPI, update its source version/checksum above,
# rebuild the image and redeploy
# (offline: run pull-and-save-images.sh, transfer tracepcap-backend.tar, load-images.sh).
#
# Cache package lists, not all of /var/lib/apt: extended_states tracks each
# stage's manual/automatic packages and must not leak from ndpi-build here.
# BuildKit cache mounts keep downloaded apt packages cached across rebuilds.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        tshark \
        tzdata \
        gosu \
        suricata \
        libpcap0.8 \
        libjson-c5 \
        libpcre2-8-0 && \
    dpkg-query -W -f='${Version}' suricata > /opt/suricata-version

COPY --from=ndpi-build /out/ndpiReader /usr/local/bin/ndpiReader
COPY --from=ndpi-build /out/ndpi-version /opt/ndpi-version

# Fetch the Emerging Threats Open ruleset at build time (internet is available during build,
# same curl pattern as the DB-IP MMDB download below). The jammy `suricata` package does not bundle
# `suricata-update`, so we download the ET Open tarball directly and concatenate every *.rules file
# into /etc/suricata/rules/suricata.rules — the path the packaged /etc/suricata/suricata.yaml
# already references (default-rule-path: /etc/suricata/rules + `rule-files: [suricata.rules]`). ET's
# classification / reference configs are copied into /etc/suricata so rule classtypes resolve. This keeps
# signature-based detection fully offline at runtime (per the offline requirement).
#
# Rules are made world-readable so the non-root `spring` runtime user can load them.
#
# To refresh the ruleset in air-gapped deployments: rebuild the image and redeploy
# (offline: run pull-and-save-images.sh, transfer tracepcap-backend.tar, load-images.sh) —
# analogous to the nDPI refresh flow above.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl && \
    mkdir -p /etc/suricata/rules /tmp/etrules && \
    curl -fsSL "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" \
        | tar -xz -C /tmp/etrules && \
    cat /tmp/etrules/rules/*.rules > /etc/suricata/rules/suricata.rules && \
    cp /tmp/etrules/rules/*.config /etc/suricata/ 2>/dev/null || true && \
    rm -rf /tmp/etrules && \
    date -u +%Y-%m-%d > /opt/suricata-ruleset-version && \
    chmod -R a+rX /etc/suricata && \
    apt-get purge -y --auto-remove curl

# Download DB-IP Lite City MMDB (offline GeoIP).
# Published monthly at https://db-ip.com/db/download/ip-to-city-lite
# Try current month; fall back to previous month if not yet published.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl && \
    mkdir -p /app/geoip && \
    CUR_YM=$(date +%Y-%m) && \
    PREV_YM=$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m) && \
    curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${CUR_YM}.mmdb.gz" \
        | gunzip -c > /app/geoip/dbip-city-lite.mmdb \
    || curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${PREV_YM}.mmdb.gz" \
        | gunzip -c > /app/geoip/dbip-city-lite.mmdb && \
    apt-get purge -y --auto-remove curl

# Check the reader after all apt cleanup, which must preserve its runtime libraries.
# The reader exits 1 after printing help, so check its version banner instead.
RUN ndpiReader --help 2>&1 | grep -F 'Welcome to nDPI 5.0.0'

# Set timezone to Singapore
ENV TZ=Asia/Singapore
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Create a non-root user
RUN groupadd -r spring && useradd -r -g spring spring

# Create config directories owned by spring
RUN mkdir -p /app/config /app/config-defaults && chown spring:spring /app/config /app/config-defaults

# Copy entrypoint script and make executable while still root
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Copy the built JAR from build stage
COPY --from=build /app/target/*.jar app.jar

# Copy the default signatures file into both locations:
# - /app/config/signatures.yml  — picked up by Docker on first-time named volume init
# - /app/config-defaults/       — fallback used by entrypoint if volume file is missing
COPY --chown=spring:spring config/signatures.yml /app/config/signatures.yml
COPY --chown=spring:spring config/signatures.yml /app/config-defaults/signatures.yml

# Expose the application port
EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]

# syntax=docker/dockerfile:1.7

# --- Build stage: produce quarkus distribution zip ---
FROM eclipse-temurin:21-jdk-jammy AS build

ARG MAVEN_OPTS
ENV MAVEN_OPTS="-Dmaven.repo.local=/root/.m2/repository -Xmx2g ${MAVEN_OPTS}"

WORKDIR /workspace

# Pre-copy Maven wrapper and root POM for dependency resolution caching
COPY mvnw mvnw.cmd ./
RUN chmod +x mvnw && sed -i 's/\r$//' mvnw
COPY .mvn/ .mvn/
COPY pom.xml ./

# Pre-copy module POMs likely referenced during build to leverage Docker layer cache
COPY quarkus/pom.xml quarkus/pom.xml
COPY quarkus/dist/pom.xml quarkus/dist/pom.xml
COPY quarkus/deployment/pom.xml quarkus/deployment/pom.xml
COPY quarkus/runtime/pom.xml quarkus/runtime/pom.xml
COPY quarkus/server/pom.xml quarkus/server/pom.xml

# Copy the rest of the source
COPY . .

# Ensure wrapper remains executable and with LF endings after copying full source (Windows hosts)
RUN chmod +x mvnw && sed -i 's/\r$//' mvnw

# Build only the Quarkus distribution to speed up container builds
RUN ./mvnw -B -e -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install

# The zip distribution will be at quarkus/dist/target


# --- Runtime stage: minimal JRE with server installed ---
FROM eclipse-temurin:21-jre-jammy AS runtime

ENV KC_HOME=/opt/iamshield \
    JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+UseContainerSupport"

RUN useradd --system --create-home --home-dir ${KC_HOME} --shell /sbin/nologin iamshield

WORKDIR ${KC_HOME}

# Copy and unpack the distribution
COPY --from=build /workspace/quarkus/dist/target/*.zip /tmp/iamshield.zip
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends unzip; \
    unzip -q /tmp/iamshield.zip -d /opt; \
    rm -f /tmp/iamshield.zip; \
    mv /opt/iamshield-* ${KC_HOME}/dist; \
    chown -R iamshield:iamshield ${KC_HOME}; \
    apt-get purge -y unzip && rm -rf /var/lib/apt/lists/*

# Provide an entrypoint that supports either iamshield.sh or kc.sh (before switching user)
RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'BIN_DIR="${KC_HOME}/dist/bin"' \
    'if [ -x "${BIN_DIR}/iamshield.sh" ]; then' \
    '  exec "${BIN_DIR}/iamshield.sh" "$@"' \
    'elif [ -x "${BIN_DIR}/kc.sh" ]; then' \
    '  exec "${BIN_DIR}/kc.sh" "$@"' \
    'else' \
    '  echo "No startup script found in ${BIN_DIR} (iamshield.sh or kc.sh)" >&2' \
    '  exit 1' \
    'fi' \
    > /usr/local/bin/iamshield-entrypoint && chmod +x /usr/local/bin/iamshield-entrypoint

# Expose default HTTP/HTTPS and debug ports
EXPOSE 8080 8443 8787

USER iamshield

# Default to start in dev; override with "start" for production
ENTRYPOINT ["/usr/local/bin/iamshield-entrypoint"]
CMD ["start-dev"]



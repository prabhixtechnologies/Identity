# syntax=docker/dockerfile:1

# Base images come from AWS's public gallery rather than Docker Hub. These are the same
# Docker Official Images, mirrored by AWS, and the move takes Docker Hub's anonymous pull
# limit off the build path: a rate-limited base image fails the build for a reason that has
# nothing to do with the change being built.

# ---------------------------------------------------------------------------
# Stage 1 — build the Spring Boot fat JAR with a cacheable dependency layer.
# ---------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

# Resolve dependencies first so code-only changes reuse this layer.
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B -DskipTests package

# ---------------------------------------------------------------------------
# Stage 2 — minimal JRE runtime, non-root, container-aware JVM flags.
# ---------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/eclipse-temurin:25-jre-alpine AS runtime

# curl is only used by HEALTHCHECK; kept out of the build stage.
RUN apk add --no-cache curl \
    && addgroup -g 1001 prabhix \
    && adduser -u 1001 -G prabhix -s /bin/sh -D prabhix

WORKDIR /app

COPY --from=build --chown=prabhix:prabhix /build/target/prabhix-identity.jar ./app.jar

USER prabhix

EXPOSE 8081

# Let the JVM size itself from cgroup memory limits instead of a fixed -Xmx.
#
# Signing is RSA, so the JVM draws from the system random source on every token. /dev/./urandom
# keeps that non-blocking — the container has far less entropy available than a desktop, and
# blocking here would stall sign-in for every product at once.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom"

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8081/actuator/health/readiness || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]

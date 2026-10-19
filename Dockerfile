# Multi-stage build for the iter8-oauth authorization server (as-app). Gradle build (JDK 25) -> slim JRE.
# The build stage uses the committed Gradle wrapper, so the Gradle version is pinned by the repo.
#
# Starting point: no dependency or build cache is wired, so each build re-downloads Gradle and
# dependencies. Add a Gradle build cache (or switch to Jib, as oura-mcp does) when build time matters.

FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

# Wrapper + build config first, then every module the as-app bootJar needs.
COPY gradlew settings.gradle.kts gradle.properties ./
COPY gradle ./gradle
COPY buildSrc ./buildSrc
COPY cimd ./cimd
COPY token ./token
COPY oauth-core ./oauth-core
COPY resource-server ./resource-server
COPY as-app ./as-app

RUN ./gradlew --no-daemon :as-app:bootJar

FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app

# Only the executable bootJar exists in as-app/build/libs (the plain jar is disabled by convention).
COPY --from=build /workspace/as-app/build/libs/*.jar /app/app.jar

# Cloud Run and most container platforms send traffic to 8080.
EXPOSE 8080
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseSerialGC"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]

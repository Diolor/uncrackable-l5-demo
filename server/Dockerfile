# First run ./gradlew :server:installDist with Java 21 from the repository root.
# Build using: docker build -f server/Dockerfile -t uncrackable-l5 .
# Resolve and pin an approved base digest before release.
FROM gcr.io/distroless/java21-debian12:nonroot
WORKDIR /app
COPY --chown=65532:65532 server/build/install/server/lib/ /app/lib/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-cp", "/app/lib/*", "org.owasp.uncrackable.server.MainKt"]

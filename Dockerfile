FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /src
COPY . .
RUN ./gradlew -PserverOnly :server:test :server:installDist --no-daemon

FROM gcr.io/distroless/java21-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=65532:65532 /src/server/build/install/server/lib/ /app/lib/
USER 65532:65532
EXPOSE 10000
ENTRYPOINT ["java", "-Xmx256m", "-cp", "/app/lib/*", "org.owasp.uncrackable.server.RenderDemoMainKt"]

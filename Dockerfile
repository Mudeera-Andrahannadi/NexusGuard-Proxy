# Stage 1: compile with the JDK. Tests run in CI, so only application code is built here.
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY src/main/java src/main/java
RUN find src/main/java -name '*.java' > sources.txt \
 && javac -encoding UTF-8 --release 17 -d /out @sources.txt

# Stage 2: run on the small JRE image, as a non-root user.
FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S netguard && adduser -S -G netguard netguard \
 && mkdir -p /app/data /app/config \
 && chown -R netguard:netguard /app
WORKDIR /app
COPY --from=build /out /app/classes
USER netguard

# 8888 proxy, 8181 dashboard (no login: publish it to localhost only).
EXPOSE 8888 8181
VOLUME /app/data

# The app refuses 0.0.0.0, so bind to the container's own private address. Extra flags go in CMD.
ENTRYPOINT ["sh", "-c", "IP=$(hostname -i | cut -d' ' -f1); exec java -XX:MaxRAMPercentage=75 -cp /app/classes com.demo.netguard.NetGuardApp --bind \"$IP\" --dashboard-bind \"$IP\" \"$@\"", "netguard"]
CMD []

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://$(hostname -i | cut -d' ' -f1):8181/health" || exit 1

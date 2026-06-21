# Stage 1: extract layers
FROM eclipse-temurin:17-jre-alpine AS builder
WORKDIR /builder
ARG JAR_FILE=build/libs/*[^plain].jar
COPY ${JAR_FILE} application.jar
RUN java -Djarmode=tools -jar application.jar extract --layers --destination extracted

# Stage 2: minimal runtime
FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S spring && adduser -S spring -G spring
USER spring
WORKDIR /app
COPY --from=builder /builder/extracted/dependencies/          ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/           ./
ENTRYPOINT ["java", "-jar", "application.jar"]

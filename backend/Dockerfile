# Build Stage
FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /app
COPY pom.xml .

# Copy src/main specifically since your repo only has src/main
COPY src/main ./src/main

RUN mvn --batch-mode --no-transfer-progress -DskipTests package

# Run Stage
FROM eclipse-temurin:17-jre

WORKDIR /app

# Use wildcard so any jar name matches
COPY --from=build /app/target/*.jar app.jar

RUN useradd --system --uid 10001 appuser
USER appuser

ENV SPRING_PROFILES_ACTIVE=uat
EXPOSE 8080

# Keep JVM heap bounded within Render's 512MB RAM limit
ENTRYPOINT ["java", "-Xms128m", "-Xmx320m", "-jar", "/app/app.jar"]

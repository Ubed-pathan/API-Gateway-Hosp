# Stage 1: Build the application
FROM maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml and resolve dependencies
COPY pom.xml .
RUN mvn dependency:resolve

# Copy source code
COPY src ./src

# Build the jar
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy jar from build stage
COPY --from=build /app/target/api-gateway-0.0.1-SNAPSHOT.jar app.jar

# Install bash for environment variable support
RUN apk add --no-cache bash

# Copy optional .env file if you want to bake default env values
# COPY .env .env

# Expose API Gateway port
EXPOSE 1115

# Run the jar with environment variable support
ENTRYPOINT ["bash", "-c", "set -a && [ -f /app/.env ] && source /app/.env; exec java -jar app.jar"]

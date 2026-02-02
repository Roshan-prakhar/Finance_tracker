FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Install Maven
RUN apk add --no-cache maven

COPY pom.xml ./
RUN mvn dependency:go-offline -B

COPY src ./src

RUN mvn clean package -DskipTests

# Explicit port configuration
EXPOSE 8080
ENV PORT=8080

CMD ["sh", "-c", "java -jar target/moneymanager-0.0.1-SNAPSHOT.jar --server.port=$PORT"]

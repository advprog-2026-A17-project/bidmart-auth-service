FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

COPY build/libs/bidmartauthservice-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]


FROM swr.cn-north-4.myhuaweicloud.com/oomall-javaee/openjdk:21-alpine

WORKDIR /app
COPY target/rbac-service-1.0.0.jar /app/rbac-service.jar

EXPOSE 8080 8081
ENTRYPOINT ["java", "-jar", "/app/rbac-service.jar"]

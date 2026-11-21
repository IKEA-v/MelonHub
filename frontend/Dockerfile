FROM swr.cn-north-4.myhuaweicloud.com/oomall-javaee/openjdk:21-alpine

COPY dist /app
COPY StaticServer.java /tmp/StaticServer.java
RUN javac /tmp/StaticServer.java

EXPOSE 80
CMD ["java", "-cp", "/tmp", "StaticServer", "/app", "80"]

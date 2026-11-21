import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * 为 Swarm 静态前端镜像提供最小 HTTP 文件服务。
 */
public final class StaticServer {

    private static final Map<String, String> CONTENT_TYPES = Map.of(
            ".html", "text/html; charset=UTF-8",
            ".js", "application/javascript; charset=UTF-8",
            ".css", "text/css; charset=UTF-8",
            ".json", "application/json; charset=UTF-8",
            ".png", "image/png",
            ".svg", "image/svg+xml"
    );

    private StaticServer() {
    }

    /**
     * 启动静态文件服务。
     *
     * @param arguments 根目录和端口
     * @throws Exception 启动失败
     */
    public static void main(String[] arguments) throws Exception {
        Path root = Path.of(arguments[0]).toAbsolutePath().normalize();
        int port = Integer.parseInt(arguments[1]);
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", exchange -> serve(exchange, root));
        server.start();
    }

    private static void serve(HttpExchange exchange, Path root) throws IOException {
        String requestPath = exchange.getRequestURI().getPath();
        String relative = requestPath.equals("/") ? "index.html" : requestPath.substring(1);
        Path candidate = root.resolve(relative).normalize();
        if (!candidate.startsWith(root) || !Files.isRegularFile(candidate)) {
            candidate = root.resolve("index.html");
        }
        byte[] content = Files.readAllBytes(candidate);
        String suffix = candidate.getFileName().toString();
        int dot = suffix.lastIndexOf('.');
        String contentType = dot >= 0 ? CONTENT_TYPES.getOrDefault(suffix.substring(dot), "application/octet-stream") : "application/octet-stream";
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, content.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }
}

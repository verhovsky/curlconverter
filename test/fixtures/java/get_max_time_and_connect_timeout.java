import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

HttpClient client = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(13.9999))
    .build();

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("http://localhost:28139"))
    .GET()
    .timeout(Duration.ofSeconds(6.72))
    .build();

HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

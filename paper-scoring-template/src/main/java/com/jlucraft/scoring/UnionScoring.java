package com.jlucraft.scoring;

import com.google.gson.Gson;
import org.bukkit.plugin.java.JavaPlugin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Gameplay plugins call this API. It does not authenticate, route, or replace players. */
public final class UnionScoring extends JavaPlugin {
    private final Gson json = new Gson();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    private final ThreadPoolExecutor queue = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(256));
    private URI endpoint;
    private String token;
    private String league;

    @Override public void onEnable() {
        saveDefaultConfig();
        endpoint = URI.create(getConfig().getString("endpoint", "http://127.0.0.1:8091"));
        token = System.getenv("UNION_SCORING_TOKEN");
        league = getConfig().getString("league");
        if (!"http".equals(endpoint.getScheme()) || !"127.0.0.1".equals(endpoint.getHost()) || endpoint.getUserInfo()!=null || token==null || token.length()<32 || league==null) {
            getLogger().severe("Configure loopback scoring endpoint, league and UNION_SCORING_TOKEN");
            getServer().getPluginManager().disablePlugin(this);
        }
    }
    /** eventId must be persisted by the game mode and reused unchanged on retry. */
    public CompletableFuture<Void> score(String eventId, Map<String, Long> players, Map<String, Long> teams) {
        return submit("/v1/score", Map.of("league", league, "event", eventId, "players", Map.copyOf(players), "teams", Map.copyOf(teams)));
    }
    /** Queue finish after all scores; a failure must be resolved before declaring completion. */
    public CompletableFuture<Void> finish() { return submit("/v1/finish", Map.of("league", league)); }
    private CompletableFuture<Void> submit(String path, Object payload) {
        final CompletableFuture<Void> result = new CompletableFuture<>();
        final String body = json.toJson(payload);
        if (!isEnabled()) return CompletableFuture.failedFuture(new IllegalStateException("Scoring disabled"));
        try {
            queue.execute(() -> {
                try {
                    HttpRequest request = HttpRequest.newBuilder(endpoint.resolve(path)).timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
                    var response = http.send(request, HttpResponse.BodyHandlers.discarding());
                    if (response.statusCode()!=204) throw new IllegalStateException("Score rejected: HTTP " + response.statusCode());
                    result.complete(null);
                } catch (InterruptedException error) { Thread.currentThread().interrupt(); result.completeExceptionally(error); }
                catch (Exception error) { result.completeExceptionally(error); }
            });
        } catch (java.util.concurrent.RejectedExecutionException error) { result.completeExceptionally(error); }
        return result;
    }
    @Override public void onDisable() { queue.shutdown(); }
}

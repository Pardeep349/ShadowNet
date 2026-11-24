
package com.shadownetx;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.StreamSupport;

/** Console entry point and user workflow for ShadowNetX. */
public final class ShadowNetX {
    private static final int DEFAULT_PORT = 8443;
    private static final Path STATE = Path.of(System.getProperty("user.home"), ".shadownetx");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Scanner INPUT = new Scanner(System.in, StandardCharsets.UTF_8);

    private ShadowNetX() {}

    public static void main(String[] args) {
        System.out.println("=== ShadowNetX | Live group chat ===");
        try {
            if (args.length > 0 && args[0].equalsIgnoreCase("server")) runServer();
            else runClient();
        } catch (Exception exception) {
            System.out.println("ShadowNetX: " + safeMessage(exception));
            System.exit(1);
        }
    }

    private static void runServer() throws Exception {
        String databaseUrl = System.getenv().getOrDefault("SHADOWNETX_DB_URL",
                "jdbc:mysql://127.0.0.1:3306/shadownetx?serverTimezone=UTC");
        String databaseUser = System.getenv().getOrDefault("SHADOWNETX_DB_USER", "shadownetx_app");
        String configuredPassword = System.getenv("SHADOWNETX_DB_PASSWORD");
        char[] databasePassword = configuredPassword == null
                ? readPassword("MySQL password for " + databaseUser + ": ")
                : configuredPassword.toCharArray();
        int serverPort = Integer.parseInt(System.getenv().getOrDefault("SHADOWNETX_SERVER_PORT", String.valueOf(DEFAULT_PORT)).trim());
        if (serverPort < 1 || serverPort > 65535) throw new IllegalArgumentException("SHADOWNETX_SERVER_PORT must be between 1 and 65535.");
        try {
            try (ChatServer server = new ChatServer(STATE, serverPort, databaseUrl, databaseUser,
                    new String(databasePassword))) {
                server.start();
                List<String> addresses = lanAddresses();
                if (addresses.isEmpty()) System.out.println("Server address: localhost");
                else addresses.forEach(address -> System.out.println("Server address: " + address + ":" + server.port()));
                System.out.println("For remote invited users, install Tailscale on this Mac and each client device.");
                System.out.println("Clients should set SHADOWNETX_SERVER_HOST to this Mac's Tailscale IP or MagicDNS name.");
                System.out.println("Share this certificate SHA-256 fingerprint with each invited user over a trusted channel:");
                System.out.println(server.certificateFingerprint());
                System.out.println("Keep this window open while users connect. Press Enter here to stop the server.");
                INPUT.nextLine();
            }
            System.out.println("Server stopped. Live messages and invitations were cleared.");
        } finally {
            java.util.Arrays.fill(databasePassword, '\0');
        }
    }

    private static void runClient() throws Exception {
        String host = System.getenv().getOrDefault("SHADOWNETX_SERVER_HOST", "127.0.0.1").trim();
        int port = Integer.parseInt(System.getenv().getOrDefault("SHADOWNETX_SERVER_PORT", String.valueOf(DEFAULT_PORT)).trim());
        if (host.isBlank() || host.contains("/")) throw new IllegalArgumentException("Set SHADOWNETX_SERVER_HOST to the server's LAN or Tailscale IP/DNS name.");
        String pin = System.getenv("SHADOWNETX_SERVER_PIN");
        if (pin != null && !pin.isBlank()) {
            pin = TransportSecurity.normalize(pin);
            savePin(host, port, pin);
        } else {
            pin = loadPin(host, port);
        }
        if (pin == null) {
            System.out.println("First connection to " + host + ":" + port + ".");
            System.out.println("Obtain the SHA-256 certificate fingerprint directly from the server owner.");
            System.out.println("Do NOT accept a fingerprint sent over the same untrusted network.");
            pin = TransportSecurity.normalize(ask("Server SHA-256 fingerprint: "));
            savePin(host, port, pin);
        }
        ApiClient api = new ApiClient(host, port, pin);
        api.request("GET", "/ping", null, null, 5000);
        System.out.println("Connected securely to ShadowNetX.");

        int userId;
        String token;
        boolean owner;
        while (true) {
            System.out.println("1. Login\n2. Register account\n3. Back");
            String choice = ask("Choose: ");
            if (choice.equals("3")) return;
            if (choice.equals("2")) { register(api); continue; }
            else if (!choice.equals("1")) { System.out.println("Choose 1, 2, or 3."); continue; }

            int enteredId = parseUserId(ask("User ID: "));
            char[] password = readPassword("Password: ");
            Map<String, Object> response;
            try { response = api.request("POST", "/login", Map.of("userId", enteredId, "password", new String(password)), null, 10000); }
            finally { java.util.Arrays.fill(password, '\0'); }
            token = asString(response.get("token"));
            userId = asInt(response.get("userId"));
            owner = Boolean.TRUE.equals(response.get("owner"));
            break;
        }

        System.out.println("Welcome, user " + userId + (owner ? " (OWNER)" : "") + ".");
        chat(api, token, userId);
        while (true) {
            System.out.println(owner
                    ? "1. Enter live room\n2. Create invitation keys\n3. View online members\n4. Change password\n5. Remove member account\n6. Logout"
                    : "1. Enter live room\n2. Change password\n3. Logout");
            String choice = ask("Select option: ");
            if (choice.equals("1")) chat(api, token, userId);
            else if (owner && choice.equals("2")) makeInvitations(api, token);
            else if (owner && choice.equals("3")) showOnlineMembers(api, token);
            else if (choice.equals(owner ? "4" : "2")) changePassword(api, token);
            else if (owner && choice.equals("5")) removeMember(api, token);
            else if (choice.equals(owner ? "6" : "3")) {
                try { api.request("POST", "/logout", Map.of(), token, 5000); } catch (Exception ignored) { }
                System.out.println("Logged out.");
                return;
            } else System.out.println("Choose a listed option.");
        }
    }

    private static void register(ApiClient api) throws Exception {
        String code = ask("Invitation key (leave blank only for the first account): ").trim();
        char[] password = readPassword("Choose password (8–128 characters): ");
        try {
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("password", new String(password));
            fields.put("invitationCode", code);
            Map<String, Object> response = api.request("POST", "/register", fields, null, 15000);
            System.out.println("Account created. Your user ID is " + asInt(response.get("userId"))
                    + ("OWNER".equals(response.get("role")) ? " (OWNER). Keep this ID." : ". Keep this ID."));
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static void makeInvitations(ApiClient api, String token) throws Exception {
        int count = parseCount(ask("How many one-use keys? "));
        Map<String, Object> response = api.request("POST", "/invitations", Map.of("count", count), token, 10000);
        List<Map<String, Object>> invites = mapList(response.get("invitations"));
        System.out.println("Share each key with one person. Keys expire in seven days:");
        for (Map<String, Object> invite : invites) System.out.println("  " + invite.get("code"));
    }

    private static void showOnlineMembers(ApiClient api, String token) throws Exception {
        Map<String, Object> response = api.request("GET", "/room/online", null, token, 5000);
        Object raw = response.get("userIds");
        int page;
        try { page = Math.max(1, Integer.parseInt(ask("Page number (20 users per page): "))); }
        catch (NumberFormatException exception) { page = 1; }
        List<Integer> pageIds = raw instanceof List<?> list
                ? sortedPage(list.stream().filter(Number.class::isInstance).map(Number.class::cast).toList(), page)
                : List.of();
        List<String> ids = pageIds.stream().map(id -> "User " + id).toList();
        System.out.println(ids.isEmpty() ? "No online members on this page." : String.join("   ", ids));
    }

    private static void changePassword(ApiClient api, String token) throws Exception {
        char[] password = readPassword("New password (8–128 characters): ");
        try {
            api.request("POST", "/password", Map.of("newPassword", new String(password)), token, 10000);
            System.out.println("Password changed.");
        } finally { java.util.Arrays.fill(password, '\0'); }
    }

    private static void removeMember(ApiClient api, String token) throws Exception {
        int userId = parseUserId(ask("Member user ID to remove: "));
        Map<String, Object> response = api.request("POST", "/users/remove", Map.of("userId", userId), token, 10000);
        System.out.println(Boolean.TRUE.equals(response.get("removed")) ? "Account removed." : "No such account.");
    }

    private static void chat(ApiClient api, String token, int userId) throws Exception {
        api.request("POST", "/room/join", Map.of(), token, 5000);
        System.out.println("[ ShadowNetX live room ]  User " + userId);
        System.out.println("Messages are encrypted in transit. No room history is loaded or saved.");
        System.out.println("Type /back to leave.");
        AtomicBoolean active = new AtomicBoolean(true);
        Thread receiver = new Thread(new Receiver(api, token, active), "shadownetx-receiver-" + userId);
        System.out.println("Receiver thread before start: " + receiver.getState());
        receiver.setDaemon(true);
        receiver.setPriority(Thread.NORM_PRIORITY);
        receiver.start();
        System.out.println("Receiver thread after start: " + receiver.getState());
        try {
            while (active.get()) {
                String message = ask("Message: ");
                if (message.equalsIgnoreCase("/back")) break;
                if (message.isBlank()) continue;
                Map<String, Object> response = api.request("POST", "/room/send", Map.of("message", message), token, 10000);
                System.out.println("[you] " + message);
            }
        } finally {
            active.set(false);
            try { api.request("POST", "/room/leave", Map.of(), token, 5000); } catch (Exception ignored) { }
            receiver.interrupt();
            receiver.join(2500);
            System.out.println("Receiver thread after room exit: " + receiver.getState());
        }
    }

    private static final class Receiver implements Runnable {
        private final ApiClient api;
        private final String token;
        private final AtomicBoolean active;
        private Receiver(ApiClient api, String token, AtomicBoolean active) { this.api = api; this.token = token; this.active = active; }
        @Override public void run() {
            while (active.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    Map<String, Object> response = api.request("GET", "/room/poll", null, token, 25000);
                    if (response == null || response.isEmpty()) continue;
                    System.out.println("\n[user " + asInt(response.get("senderId")) + "] " + asString(response.get("message")));
                } catch (Exception exception) {
                    if (!active.get() || Thread.currentThread().isInterrupted()) return;
                    System.out.println("\nRoom connection retrying: " + safeMessage(exception));
                    try { Thread.sleep(1000); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); return; }
                }
            }
        }
    }

    private static String loadPin(String host, int port) throws IOException {
        Path path = pinPath(host, port);
        if (!Files.exists(path)) return null;
        return TransportSecurity.normalize(Files.readString(path, StandardCharsets.UTF_8).trim());
    }

    private static void savePin(String host, int port, String fingerprint) throws IOException {
        Files.createDirectories(STATE.resolve("pins"));
        Files.writeString(pinPath(host, port), TransportSecurity.normalize(fingerprint), StandardCharsets.UTF_8);
    }

    private static Path pinPath(String host, int port) {
        String safeHost = host.replaceAll("[^A-Za-z0-9._-]", "_");
        return STATE.resolve("pins").resolve(safeHost + "-" + port + ".pin");
    }

    private static final class ApiClient {
        private final String host;
        private final int port;
        private final SSLContext tls;
        private ApiClient(String host, int port, String pin) throws Exception {
            this.host = host; this.port = port;
            this.tls = TransportSecurity.pinnedClientContext(pin);
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> request(String method, String endpoint, Object body, String token, int timeoutMs) throws Exception {
            String baseHost = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
            URL url = new URL("https://" + baseHost + ":" + port + "/api" + endpoint);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(tls.getSocketFactory());
            connection.setHostnameVerifier((ignoredHost, session) -> true); // The pinned SHA-256 certificate authenticates this server.
            connection.setRequestMethod(method);
            connection.setConnectTimeout(6000);
            connection.setReadTimeout(timeoutMs);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Cache-Control", "no-store");
            if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
            if (body != null) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                try (OutputStream output = connection.getOutputStream()) { JSON.writeValue(output, body); }
            }
            try {
                int status = connection.getResponseCode();
                if (status == 204) return Map.of();
                InputStream stream = status < 400 ? connection.getInputStream() : connection.getErrorStream();
                if (stream == null) return Map.of();
                try (stream) {
                    Map<String, Object> response = JSON.readValue(stream, new TypeReference<>() {});
                    if (status >= 400) throw new IOException(asString(response.getOrDefault("error", "Request failed.")));
                    ApiResult<Map<String, Object>> result = new ApiResult<>(status, response);
                    return result.body();
                }
            } finally { connection.disconnect(); }
        }
    }

    private static List<Map<String, Object>> mapList(Object raw) {
        List<Map<String, Object>> values = new ArrayList<>();
        if (raw instanceof List<?> list) for (Object item : list) if (item instanceof Map<?, ?> map) {
            Map<String, Object> copy = new HashMap<>();
            map.forEach((key, value) -> copy.put(String.valueOf(key), value));
            values.add(copy);
        }
        values.sort(Comparator.comparing(item -> asString(item.get("expiresAt"))));
        return values;
    }

    private static String ask(String prompt) {
        System.out.print(prompt);
        return INPUT.hasNextLine() ? INPUT.nextLine().strip() : "3";
    }

    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] value = console.readPassword("%s", prompt);
            return value == null ? new char[0] : value;
        }
        return ask(prompt).toCharArray();
    }

    private static int parseUserId(String value) {
        int id = Integer.parseInt(value);
        if (id < 1) throw new IllegalArgumentException("User ID must be positive.");
        return id;
    }

    private static int parseCount(String value) {
        int count = Integer.parseInt(value);
        if (count < 1 || count > 50) throw new IllegalArgumentException("Enter a count from 1 to 50.");
        return count;
    }

    private static <T extends Number> List<Integer> sortedPage(Iterable<T> values, int page) {
        long skip = (long)(page - 1) * 20;
        return StreamSupport.stream(values.spliterator(), false).map(Number::intValue)
                .distinct().sorted().skip(skip).limit(20).toList();
    }

    private static String asString(Object value) { return value == null ? "" : String.valueOf(value); }
    private static int asInt(Object value) { return value instanceof Number number ? number.intValue() : Integer.parseInt(asString(value)); }
    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) return exception.getClass().getSimpleName();
        return message;
    }

    private static List<String> lanAddresses() throws Exception {
        List<String> addresses = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface network = interfaces.nextElement();
            if (!network.isUp() || network.isLoopback()) continue;
            Enumeration<InetAddress> candidates = network.getInetAddresses();
            while (candidates.hasMoreElements()) {
                InetAddress address = candidates.nextElement();
                if (!address.isLoopbackAddress() && address instanceof java.net.Inet4Address) addresses.add(address.getHostAddress());
            }
        }
        TreeSet<String> distinct = new TreeSet<>(addresses);
        return List.copyOf(distinct);
    }

    private record ApiResult<T>(int statusCode, T body) {}
}

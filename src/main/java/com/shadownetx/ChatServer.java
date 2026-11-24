package com.shadownetx;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/** HTTPS API and transient one-room broker. */
public final class ChatServer implements AutoCloseable {
    private static final int MAX_BODY_BYTES = 16_384;
    private static final int MAX_MESSAGE_CHARS = 500;
    private final ObjectMapper json = new ObjectMapper();
    private final UserDatabase database;
    private final PasswordService passwords = new PasswordService();
    private final InvitationManager invitations = new InvitationManager();
    private final LiveRoom room = new LiveRoom();
    private final Map<String, Integer> sessions = new ConcurrentHashMap<>();
    private final HttpsServer server;
    private final ExecutorService workers;
    private final String fingerprint;

    public ChatServer(Path stateDirectory, int port, String databaseUrl, String databaseUser,
                      String databasePassword) throws Exception {
        this(stateDirectory, port, new UserDatabase(databaseUrl, databaseUser, databasePassword));
    }

    ChatServer(Path stateDirectory, int port, UserDatabase database) throws Exception {
        Files.createDirectories(stateDirectory);
        try {
            Files.setPosixFilePermissions(stateDirectory, java.util.EnumSet.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException ignored) { }
        this.database = database;
        TransportSecurity.ServerTls tls = TransportSecurity.serverContext(stateDirectory);
        fingerprint = tls.fingerprint();
        server = HttpsServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls.context()));
        server.createContext("/api/", this::handle);
        AtomicInteger counter = new AtomicInteger();
        ThreadFactory factory = task -> {
            Thread thread = new Thread(task, "shadownetx-request-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        workers = Executors.newFixedThreadPool(16, factory);
        server.setExecutor(workers);
    }

    public void start() {
        server.start();
        System.out.println("ShadowNetX HTTPS server ready on port " + server.getAddress().getPort());
        System.out.println("Share this SHA-256 fingerprint with clients for first connection:");
        System.out.println(fingerprint);
        System.out.println("Only user IDs and salted password hashes are stored in MySQL.");
    }

    public int port() { return server.getAddress().getPort(); }
    public String certificateFingerprint() { return fingerprint; }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if (path.equals("/api/ping") && method.equals("GET")) {
                send(exchange, 200, Map.of("status", "ready", "app", "ShadowNetX"));
                return;
            }
            if (path.equals("/api/register") && method.equals("POST")) { register(exchange); return; }
            if (path.equals("/api/login") && method.equals("POST")) { login(exchange); return; }
            if (path.equals("/api/logout") && method.equals("POST")) { logout(exchange); return; }
            if (path.equals("/api/password") && method.equals("POST")) { changePassword(exchange); return; }
            if (path.equals("/api/users/remove") && method.equals("POST")) { removeUser(exchange); return; }
            if (path.equals("/api/invitations") && method.equals("POST")) { createInvitations(exchange); return; }
            if (path.equals("/api/room/join") && method.equals("POST")) { joinRoom(exchange); return; }
            if (path.equals("/api/room/send") && method.equals("POST")) { sendRoomMessage(exchange); return; }
            if (path.equals("/api/room/poll") && method.equals("GET")) { pollRoom(exchange); return; }
            if (path.equals("/api/room/leave") && method.equals("POST")) { leaveRoom(exchange); return; }
            if (path.equals("/api/room/online") && method.equals("GET")) { onlineMembers(exchange); return; }
            send(exchange, 404, Map.of("error", "Unknown ShadowNetX endpoint."));
        } catch (ValidationException exception) {
            sendQuietly(exchange, 400, Map.of("error", exception.getMessage()));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            sendQuietly(exchange, 503, Map.of("error", "Request was interrupted."));
        } catch (SQLException exception) {
            sendQuietly(exchange, 500, Map.of("error", "Account database error."));
        } catch (GeneralSecurityException exception) {
            sendQuietly(exchange, 500, Map.of("error", "Password security operation failed."));
        } catch (RuntimeException exception) {
            sendQuietly(exchange, 400, Map.of("error", safeMessage(exception)));
        } finally {
            exchange.close();
        }
    }

    private synchronized void register(HttpExchange exchange) throws IOException, SQLException, GeneralSecurityException, ValidationException {
        Map<String, Object> body = body(exchange);
        char[] password = string(body, "password").toCharArray();
        try {
            if (password.length < 8 || password.length > 128) throw new ValidationException("Password must be 8–128 characters.");
            boolean firstAccount = database.userIds().isEmpty();
            String code = optionalString(body, "invitationCode");
            if (firstAccount) {
                if (!code.isBlank()) throw new ValidationException("The first account is created without an invitation and becomes owner.");
            } else if (!invitations.isActive(code)) {
                throw new ValidationException("A valid one-use invitation key is required.");
            }
            int id = database.createUser(passwords.hash(password));
            if (!firstAccount && !invitations.consume(code)) {
                database.deleteUser(id);
                throw new ValidationException("The invitation key expired or was already used. Please request another key.");
            }
            send(exchange, 201, Map.of("userId", id, "role", id == 1 ? "OWNER" : "MEMBER"));
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private void login(HttpExchange exchange) throws IOException, SQLException, GeneralSecurityException, ValidationException {
        Map<String, Object> body = body(exchange);
        int userId = integer(body, "userId");
        char[] password = string(body, "password").toCharArray();
        try {
            String stored = database.passwordHash(userId).orElseThrow(() -> new ValidationException("Invalid user ID or password."));
            if (!passwords.verify(password, stored)) throw new ValidationException("Invalid user ID or password.");
            String token = UUID.randomUUID().toString();
            sessions.put(token, userId);
            send(exchange, 200, Map.of("token", token, "userId", userId, "owner", userId == 1));
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private void logout(HttpExchange exchange) throws IOException, ValidationException {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        int userId = authenticate(exchange);
        if (header != null) sessions.remove(header.substring(7));
        room.leave(userId);
        send(exchange, 200, Map.of("status", "logged out"));
    }

    private void changePassword(HttpExchange exchange) throws IOException, SQLException,
            GeneralSecurityException, ValidationException {
        int userId = authenticate(exchange);
        char[] password = string(body(exchange), "newPassword").toCharArray();
        try {
            if (password.length < 8 || password.length > 128) throw new ValidationException("Password must be 8–128 characters.");
            database.updatePassword(userId, passwords.hash(password));
            send(exchange, 200, Map.of("status", "password changed"));
        } finally { java.util.Arrays.fill(password, '\0'); }
    }

    private void removeUser(HttpExchange exchange) throws IOException, SQLException, ValidationException {
        if (authenticate(exchange) != 1) throw new ValidationException("Only the owner can remove accounts.");
        int userId = integer(body(exchange), "userId");
        if (userId == 1) throw new ValidationException("The owner account cannot be removed.");
        boolean removed = database.deleteUser(userId);
        if (removed) {
            sessions.entrySet().removeIf(session -> session.getValue() == userId);
            room.leave(userId);
        }
        send(exchange, removed ? 200 : 404, Map.of("removed", removed));
    }

    private void createInvitations(HttpExchange exchange) throws IOException, ValidationException {
        int owner = authenticate(exchange);
        if (owner != 1) throw new ValidationException("Only the first registered user can create invitations.");
        int count = integer(body(exchange), "count");
        List<Map<String, Object>> result = new ArrayList<>();
        for (InvitationManager.Invitation invitation : invitations.create(count)) {
            result.add(Map.of("code", invitation.code(), "expiresAt", invitation.expiresAt().toString()));
        }
        send(exchange, 200, Map.of("invitations", result));
    }

    private void joinRoom(HttpExchange exchange) throws IOException, ValidationException {
        int userId = authenticate(exchange);
        room.join(userId);
        send(exchange, 200, Map.of("userId", userId, "members", room.memberIds()));
    }

    private void sendRoomMessage(HttpExchange exchange) throws IOException, ValidationException {
        int userId = authenticate(exchange);
        String text = string(body(exchange), "message").strip();
        if (text.isEmpty() || text.length() > MAX_MESSAGE_CHARS) {
            throw new ValidationException("Message must contain 1–500 characters.");
        }
        if (text.contains("\n") || text.contains("\r")) throw new ValidationException("Send one message per line.");
        LiveRoom.ChatMessage message = room.publish(userId, text);
        send(exchange, 201, Map.of("sequence", message.sequence(), "sentAt", message.sentAt().toString()));
    }

    private void pollRoom(HttpExchange exchange) throws IOException, InterruptedException, ValidationException {
        int userId = authenticate(exchange);
        LiveRoom.ChatMessage message = room.awaitMessage(userId, Duration.ofSeconds(20));
        if (message == null) send(exchange, 204, Map.of());
        else send(exchange, 200, Map.of("sequence", message.sequence(), "senderId", message.senderId(),
                "message", message.text(), "sentAt", message.sentAt().toString()));
    }

    private void leaveRoom(HttpExchange exchange) throws IOException, ValidationException {
        int userId = authenticate(exchange);
        room.leave(userId);
        send(exchange, 200, Map.of("status", "left"));
    }

    private void onlineMembers(HttpExchange exchange) throws IOException, ValidationException {
        if (authenticate(exchange) != 1) throw new ValidationException("Only the owner can view the live-room roster.");
        send(exchange, 200, Map.of("userIds", room.memberIds(), "display", room.formatRoster()));
    }

    private int authenticate(HttpExchange exchange) throws ValidationException {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) throw new ValidationException("Please log in first.");
        Integer id = sessions.get(header.substring(7));
        if (id == null) throw new ValidationException("Session expired. Please log in again.");
        return id;
    }

    private Map<String, Object> body(HttpExchange exchange) throws IOException, ValidationException {
        byte[] content = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (content.length > MAX_BODY_BYTES) throw new ValidationException("Request is too large.");
        try { return json.readValue(content, new TypeReference<>() {}); }
        catch (RuntimeException | IOException exception) { throw new ValidationException("Request must contain valid JSON."); }
    }

    private void send(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] bytes = json.writeValueAsBytes(value);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        if (status == 204) { exchange.sendResponseHeaders(status, -1); return; }
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) { output.write(bytes); }
    }

    private void sendQuietly(HttpExchange exchange, int status, Object value) {
        try { send(exchange, status, value); } catch (IOException ignored) { }
    }

    private static String safeMessage(RuntimeException exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? "Request could not be completed." : message;
    }

    private static String string(Map<String, Object> body, String key) throws ValidationException {
        Object value = body.get(key);
        if (!(value instanceof String text)) throw new ValidationException("Missing or invalid " + key + ".");
        return text;
    }

    private static String optionalString(Map<String, Object> body, String key) {
        Object value = body.get(key);
        return value instanceof String text ? text : "";
    }

    private static int integer(Map<String, Object> body, String key) throws ValidationException {
        Object value = body.get(key);
        if (value instanceof Number number) return number.intValue();
        try { return Integer.parseInt(String.valueOf(value)); }
        catch (NumberFormatException exception) { throw new ValidationException("Missing or invalid " + key + "."); }
    }


    @Override public void close() {
        server.stop(1);
        workers.shutdownNow();
        sessions.clear();
    }

    public static final class ValidationException extends Exception {
        public ValidationException(String message) { super(message); }
    }
}


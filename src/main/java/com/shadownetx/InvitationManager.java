package com.shadownetx;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StreamTokenizer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Set;

/** One-use invites kept in memory, with optional CSV export/import for owner delivery. */
public final class InvitationManager {
    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private final SecureRandom random = new SecureRandom();
    private final PriorityQueue<Invitation> byExpiry = new PriorityQueue<>(Comparator.comparing(Invitation::expiresAt));
    private final LinkedHashSet<String> active = new LinkedHashSet<>();
    private final Set<String> redeemed = new HashSet<>();

    public synchronized List<Invitation> create(int count) {
        if (count < 1 || count > 50) throw new IllegalArgumentException("Create between 1 and 50 keys.");
        removeExpired();
        List<Invitation> created = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String code;
            do { code = newCode(); } while (active.contains(code) || redeemed.contains(code));
            Invitation invitation = new Invitation(code, Instant.now().plusSeconds(7 * 24 * 60 * 60L));
            active.add(code);
            byExpiry.add(invitation);
            created.add(invitation);
        }
        created.sort(Comparator.naturalOrder());
        return List.copyOf(created);
    }

    public synchronized boolean isActive(String code) {
        removeExpired();
        return code != null && active.contains(code.trim().toUpperCase());
    }

    public synchronized boolean consume(String code) {
        removeExpired();
        if (code == null || code.isBlank() || !active.remove(code.trim().toUpperCase())) return false;
        redeemed.add(code.trim().toUpperCase());
        byExpiry.removeIf(invitation -> invitation.code().equalsIgnoreCase(code.trim()));
        return true;
    }

    public synchronized List<Invitation> activeInvitations() {
        removeExpired();
        List<Invitation> result = new ArrayList<>(byExpiry);
        result.sort(Comparator.naturalOrder());
        return result;
    }

    public synchronized void exportCsv(Path file) throws IOException {
        removeExpired();
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (FileWriter writer = new FileWriter(file.toFile(), StandardCharsets.UTF_8)) {
            writer.write("invitation_code,expires_at\n");
            for (Invitation invitation : activeInvitations()) {
                writer.write(invitation.code());
                writer.write(',');
                writer.write(invitation.expiresAt().toString());
                writer.write('\n');
            }
        }
    }

    public synchronized int importCsv(Path file) throws IOException {
        Set<String> imported = new LinkedHashSet<>();
        try (FileReader reader = new FileReader(file.toFile(), StandardCharsets.UTF_8)) {
            StreamTokenizer tokenizer = new StreamTokenizer(reader);
            tokenizer.resetSyntax();
            tokenizer.whitespaceChars(0, ' ');
            tokenizer.wordChars('A', 'Z');
            tokenizer.wordChars('a', 'z');
            tokenizer.wordChars('0', '9');
            tokenizer.wordChars('-', '-');
            tokenizer.wordChars('_', '_');
            tokenizer.whitespaceChars(',', ',');
            tokenizer.whitespaceChars('\n', '\n');
            tokenizer.whitespaceChars('\r', '\r');
            while (tokenizer.nextToken() != StreamTokenizer.TT_EOF) {
                if (tokenizer.ttype != StreamTokenizer.TT_WORD) continue;
                String token = tokenizer.sval.toUpperCase();
                if (token.matches("[A-HJ-NP-Z2-9]{8}") && !redeemed.contains(token)) imported.add(token);
            }
        }
        return importCodes(imported);
    }

    public synchronized int importCodes(Iterable<String> codes) {
        int added = 0;
        for (String raw : codes) {
            String code = raw == null ? "" : raw.trim().toUpperCase();
            if (!code.matches("[A-HJ-NP-Z2-9]{8}") || redeemed.contains(code)) continue;
            if (active.add(code)) {
                byExpiry.add(new Invitation(code, Instant.now().plusSeconds(7 * 24 * 60 * 60L)));
                added++;
            }
        }
        return added;
    }

    private void removeExpired() {
        Instant now = Instant.now();
        while (!byExpiry.isEmpty() && !byExpiry.peek().expiresAt().isAfter(now)) {
            active.remove(byExpiry.remove().code());
        }
    }

    private String newCode() {
        StringBuilder code = new StringBuilder(8);
        for (int i = 0; i < 8; i++) code.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        return code.toString();
    }

    public record Invitation(String code, Instant expiresAt) implements Comparable<Invitation> {
        @Override public int compareTo(Invitation other) { return expiresAt.compareTo(other.expiresAt); }
    }
}


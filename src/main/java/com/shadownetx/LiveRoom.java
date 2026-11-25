package com.shadownetx;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Queue;
import java.util.TreeSet;
import java.util.TreeMap;

/** Volatile producer/consumer room: messages exist only for connected participants. */
public final class LiveRoom {
    private static final int MAX_PENDING_PER_MEMBER = 100;
    private final Map<Integer, Deque<ChatMessage>> members = new LinkedHashMap<>();
    private long nextSequence = 1;

    public synchronized void join(int userId) {
        members.computeIfAbsent(userId, ignored -> new LinkedList<>());
    }

    public synchronized void leave(int userId) {
        members.remove(userId);
        notifyAll();
    }

    public synchronized ChatMessage publish(int senderId, String text) {
        if (!members.containsKey(senderId)) throw new IllegalStateException("Join the room before sending.");
        ChatMessage message = new ChatMessage(nextSequence++, senderId, text, Instant.now());
        members.forEach((recipientId, queue) -> {
            if (recipientId != senderId) {
                if (queue.size() >= MAX_PENDING_PER_MEMBER) queue.removeFirst();
                Queue<ChatMessage> producerQueue = queue;
                producerQueue.add(message);
            }
        });
        notifyAll();
        return message;
    }

    public synchronized ChatMessage awaitMessage(int recipientId, Duration timeout) throws InterruptedException {
        Deque<ChatMessage> queue = members.get(recipientId);
        if (queue == null) return null;
        long deadline = System.nanoTime() + timeout.toNanos();
        while (queue.isEmpty() && members.containsKey(recipientId)) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return null;
            long millis = remaining / 1_000_000;
            int nanos = (int) (remaining % 1_000_000);
            wait(millis, nanos);
        }
        return queue.isEmpty() ? null : queue.removeFirst();
    }

    public synchronized List<Integer> memberIds() {
        TreeMap<Integer, String> sorted = new TreeMap<>();
        members.keySet().forEach(id -> sorted.put(id, "User " + id));
        ArrayList<Integer> ids = new ArrayList<>(sorted.keySet());
        Collections.sort(ids, Comparator.naturalOrder());
        return Collections.unmodifiableList(ids);
    }

    /** Compact two-column roster display used in the owner room menu. */
    public synchronized String formatRoster() {
        ArrayList<Integer> ids = new ArrayList<>(members.keySet());
        ids.sort(Comparator.naturalOrder());
        String[][] grid = new String[(ids.size() + 1) / 2][2];
        ListIterator<Integer> cursor = ids.listIterator();
        while (cursor.hasNext()) {
            int index = cursor.nextIndex();
            grid[index / 2][index % 2] = "User " + cursor.next();
        }
        StringBuilder output = new StringBuilder("Online members:\n");
        for (String[] row : grid) {
            output.append(String.format("  %-16s %s%n", row[0] == null ? "" : row[0], row[1] == null ? "" : row[1]));
        }
        return output.toString();
    }

    public record ChatMessage(long sequence, int senderId, String text, Instant sentAt)
            implements Comparable<ChatMessage> {
        @Override public int compareTo(ChatMessage other) { return Long.compare(sequence, other.sequence); }
    }
}


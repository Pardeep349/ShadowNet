package com.shadownetx;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** MySQL/MariaDB persistence for account ID and salted password hash only. */
public final class UserDatabase {
    private final String jdbcUrl;
    private final String username;
    private final String password;

    public UserDatabase(String jdbcUrl, String username, String password) throws SQLException {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:mysql://")) {
            throw new SQLException("Set SHADOWNETX_DB_URL to a MySQL JDBC URL (jdbc:mysql://host:3306/shadownetx).");
        }
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("SELECT user_id FROM users LIMIT 0")) {
            statement.executeQuery().close();
        } catch (SQLException exception) {
            throw new SQLException("Could not connect to ShadowNetX MySQL or find its users table. Run db/setup.sql first, then check the database URL, user, and password.", exception);
        }
    }

    public int createUser(String passwordHash) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO users(password_hash) VALUES (?)", Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, passwordHash);
            if (statement.executeUpdate() != 1) throw new SQLException("The account was not created.");
            try (ResultSet result = statement.getGeneratedKeys()) {
                if (result.next()) return result.getInt(1);
            }
        }
        throw new SQLException("MySQL did not return the new account ID.");
    }

    public boolean updatePassword(int userId, String passwordHash) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE users SET password_hash = ? WHERE user_id = ?")) {
            statement.setString(1, passwordHash);
            statement.setInt(2, userId);
            return statement.executeUpdate() == 1;
        }
    }

    public boolean deleteUser(int userId) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("DELETE FROM users WHERE user_id = ?")) {
            statement.setInt(1, userId);
            return statement.executeUpdate() == 1;
        }
    }

    public Optional<String> passwordHash(int userId) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT password_hash FROM users WHERE user_id = ?")) {
            statement.setInt(1, userId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? Optional.of(rows.getString("password_hash")) : Optional.empty();
            }
        }
    }

    public List<Integer> userIds() throws SQLException {
        List<Integer> ids = new ArrayList<>();
        try (Connection connection = connect(); Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT user_id FROM users ORDER BY user_id")) {
            while (rows.next()) ids.add(rows.getInt("user_id"));
        }
        return ids;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }
}


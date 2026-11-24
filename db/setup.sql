
-- Run this once with a MySQL/MariaDB administrator account.
-- Replace the placeholder password with a unique, strong password first.

CREATE DATABASE IF NOT EXISTS shadownetx
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'xxxxxxxxxxxxxx'@'xxxxx'
  IDENTIFIED BY 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD';

ALTER USER 'xxxxxxxx'@'xxxxxxxx'
  IDENTIFIED BY 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD';

GRANT SELECT, INSERT, UPDATE, DELETE
  ON shadownetx.* TO 'xxxxxxx'@'xxxxxx';

USE shadownetx;

CREATE TABLE IF NOT EXISTS users (
  user_id INT NOT NULL AUTO_INCREMENT,
  password_hash VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

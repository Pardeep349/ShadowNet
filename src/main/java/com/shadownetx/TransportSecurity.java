package com.shadownetx;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/** HTTPS certificate creation and fingerprint-pinned client TLS. */
public final class TransportSecurity {
    private TransportSecurity() {}

    public static ServerTls serverContext(Path stateDirectory) throws Exception {
        Files.createDirectories(stateDirectory);
        try {
            Files.setPosixFilePermissions(stateDirectory, java.util.EnumSet.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        } catch (UnsupportedOperationException ignored) { }
        Path keyStorePath = stateDirectory.resolve("server.p12");
        Path passwordPath = stateDirectory.resolve("server-key.bin");
        if (!Files.isRegularFile(keyStorePath) || !Files.isRegularFile(passwordPath)) {
            Files.deleteIfExists(keyStorePath);
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            String password = HexFormat.of().formatHex(random);
            try (FileOutputStream output = new FileOutputStream(passwordPath.toFile())) {
                output.write(password.getBytes(StandardCharsets.UTF_8));
            }
            protectFile(passwordPath);
            String keytool = Path.of(System.getProperty("java.home"), "bin",
                    System.getProperty("os.name").toLowerCase().contains("win") ? "keytool.exe" : "keytool").toString();
            Process process = new ProcessBuilder(keytool, "-genkeypair", "-noprompt", "-alias", "shadownetx",
                    "-keyalg", "RSA", "-keysize", "2048", "-validity", "825", "-storetype", "PKCS12",
                    "-keystore", keyStorePath.toString(), "-storepass", password, "-keypass", password,
                    "-dname", "CN=ShadowNetX", "-ext", "KU=digitalSignature,keyEncipherment",
                    "-ext", "EKU=serverAuth").redirectErrorStream(true).start();
            byte[] output = process.getInputStream().readAllBytes();
            if (process.waitFor() != 0) {
                Files.deleteIfExists(keyStorePath);
                Files.deleteIfExists(passwordPath);
                throw new IOException("Could not create the local HTTPS certificate: " + new String(output, StandardCharsets.UTF_8));
            }
            protectFile(keyStorePath);
        }
        protectFile(passwordPath);
        protectFile(keyStorePath);
        String password;
        try (FileInputStream input = new FileInputStream(passwordPath.toFile())) {
            password = new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream input = new FileInputStream(keyStorePath.toFile())) {
            keyStore.load(input, password.toCharArray());
        }
        Certificate certificate = keyStore.getCertificate("shadownetx");
        javax.net.ssl.KeyManagerFactory keys = javax.net.ssl.KeyManagerFactory.getInstance(
                javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        keys.init(keyStore, password.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, new SecureRandom());
        return new ServerTls(context, fingerprint((X509Certificate) certificate));
    }

    public static SSLContext pinnedClientContext(String expectedFingerprint) throws Exception {
        String expected = normalize(expectedFingerprint);
        X509TrustManager pinning = new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                throw new java.security.cert.CertificateException("Client certificates are not used.");
            }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                if (chain == null || chain.length == 0) throw new java.security.cert.CertificateException("Server sent no certificate.");
                try {
                    if (!MessageDigest.isEqual(HexFormat.of().parseHex(expected),
                            HexFormat.of().parseHex(fingerprint(chain[0]).replace(":", "")))) {
                        throw new java.security.cert.CertificateException("Server certificate fingerprint does not match the saved pin.");
                    }
                } catch (Exception exception) {
                    if (exception instanceof java.security.cert.CertificateException certException) throw certException;
                    throw new java.security.cert.CertificateException("Could not verify the server certificate.", exception);
                }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{pinning}, new SecureRandom());
        return context;
    }

    public static String captureFingerprint(String host, int port) throws Exception {
        final X509Certificate[][] seen = new X509Certificate[1][];
        X509TrustManager capture = new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { seen[0] = chain.clone(); }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{capture}, new SecureRandom());
        HttpsURLConnection connection = (HttpsURLConnection) new java.net.URL("https://" + host + ":" + port + "/api/ping").openConnection();
        connection.setSSLSocketFactory(context.getSocketFactory());
        connection.setHostnameVerifier((ignoredHost, session) -> true); // Fingerprint comparison below authenticates the endpoint.
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        try { connection.getInputStream().close(); }
        finally { connection.disconnect(); }
        if (seen[0] == null || seen[0].length == 0) throw new IOException("Server certificate was not received.");
        return fingerprint(seen[0][0]);
    }

    public static String fingerprint(X509Certificate certificate) throws Exception {
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(
                MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }

    public static String normalize(String fingerprint) {
        String value = fingerprint == null ? "" : fingerprint.replace(":", "").replace(" ", "").toUpperCase();
        if (!value.matches("[0-9A-F]{64}")) throw new IllegalArgumentException("Enter the 64-digit SHA-256 fingerprint shown by the server owner.");
        return value;
    }

    private static void protectFile(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, java.util.EnumSet.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) { }
    }

    public record ServerTls(SSLContext context, String fingerprint) {}
}


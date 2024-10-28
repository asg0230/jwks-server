import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

public class JWKSServer {

    private static final String DB_URL = "jdbc:sqlite:totally_not_my_privateKeys.db";
    private static Connection connection = null;

    public static void main(String[] args) throws Exception {
        // Initialize SQLite DB
        initializeDatabase();

        // Generate and store RSA key pairs
        storeKey(RsaJwkGenerator.generateJwk(2048), 3600); // Key expiring in 1 hour
        storeKey(RsaJwkGenerator.generateJwk(2048), -1); // Expired key

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler());
        server.createContext("/auth", new AuthHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    private static void initializeDatabase() {
        try {
            connection = DriverManager.getConnection(DB_URL);
            String createTableSQL = "CREATE TABLE IF NOT EXISTS keys(\n" +
                    "    kid INTEGER PRIMARY KEY AUTOINCREMENT,\n" +
                    "    key BLOB NOT NULL,\n" +
                    "    exp INTEGER NOT NULL\n" +
                    ")";
            try (PreparedStatement stmt = connection.prepareStatement(createTableSQL)) {
                stmt.execute();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void storeKey(RsaJsonWebKey rsaJsonWebKey, int expirationSeconds) {
        try {
            String insertKeySQL = "INSERT INTO keys (key, exp) VALUES (?, ?)";
            try (PreparedStatement stmt = connection.prepareStatement(insertKeySQL)) {
                // Convert the RSA private key to a PEM string
                String pem = convertPrivateKeyToPem(rsaJsonWebKey.getPrivateKey());
                stmt.setBytes(1, pem.getBytes());
                stmt.setInt(2, (int) (System.currentTimeMillis() / 1000) + expirationSeconds);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static String convertPrivateKeyToPem(PrivateKey privateKey) {
        String base64EncodedKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PRIVATE KEY-----\n");
        int index = 0;
        while (index < base64EncodedKey.length()) {
            pem.append(base64EncodedKey, index, Math.min(index + 64, base64EncodedKey.length())).append("\n");
            index += 64;
        }
        pem.append("-----END PRIVATE KEY-----");
        return pem.toString();
    }

    private static RsaJsonWebKey getKey(boolean expired) {
        try {
            String selectKeySQL = "SELECT kid, key FROM keys WHERE exp ";
            selectKeySQL += expired ? "<= ?" : "> ?";
            try (PreparedStatement stmt = connection.prepareStatement(selectKeySQL)) {
                stmt.setInt(1, (int) (System.currentTimeMillis() / 1000));
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    String pem = new String(rs.getBytes("key"));
                    PrivateKey privateKey = convertPemToPrivateKey(pem);
    
                    // Create an RsaJsonWebKey using the JsonWebKey.Factory
                    RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(privateKey);
                    rsaJsonWebKey.setKeyId(String.valueOf(rs.getInt("kid")));
                    return rsaJsonWebKey;
                }
            }
        } catch (SQLException | JoseException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private static PrivateKey convertPemToPrivateKey(String pem) {
        try {
            String base64Key = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // JWKSHandler static inner class
    static class JWKSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"GET".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
            try {
                String selectKeysSQL = "SELECT kid, key FROM keys WHERE exp > ?";
                try (PreparedStatement stmt = connection.prepareStatement(selectKeysSQL)) {
                    stmt.setInt(1, (int) (System.currentTimeMillis() / 1000));
                    ResultSet rs = stmt.executeQuery();
                    while (rs.next()) {
                        String pem = new String(rs.getBytes("key"));
                        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(pem);
                        rsaJsonWebKey.setKeyId(String.valueOf(rs.getInt("kid")));
                        jsonWebKeySet.addJsonWebKey(rsaJsonWebKey);
                    }
                }
            } catch (SQLException | JoseException e) {
                e.printStackTrace();
                t.sendResponseHeaders(500, -1); // 500 Internal Server Error
                return;
            }

            String jwks = jsonWebKeySet.toJson();
            t.getResponseHeaders().add("Content-Type", "application/json");
            t.sendResponseHeaders(200, jwks.length());
            OutputStream os = t.getResponseBody();
            os.write(jwks.getBytes());
            os.close();
        }
    }

    // AuthHandler static inner class
    static class AuthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            if (!"POST".equalsIgnoreCase(t.getRequestMethod())) {
                t.sendResponseHeaders(405, -1); // 405 Method Not Allowed
                return;
            }

            boolean expired = t.getRequestURI().getQuery() != null && t.getRequestURI().getQuery().contains("expired=true");
            RsaJsonWebKey rsaJsonWebKey = getKey(expired);
            if (rsaJsonWebKey == null) {
                t.sendResponseHeaders(500, -1); // 500 Internal Server Error
                return;
            }

            JwtClaims claims = new JwtClaims();
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setSubject("sampleUser");
            claims.setExpirationTimeMinutesInTheFuture(10);

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
            jws.setKey(rsaJsonWebKey.getPrivateKey());
            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            String jwt = "";
            try {
                jwt = jws.getCompactSerialization();
            } catch (JoseException e) {
                e.printStackTrace();
                t.sendResponseHeaders(500, -1); // 500 Internal Server Error
                return;
            }

            t.sendResponseHeaders(200, jwt.length());
            OutputStream os = t.getResponseBody();
            os.write(jwt.getBytes());
            os.close();
        }
    }
}

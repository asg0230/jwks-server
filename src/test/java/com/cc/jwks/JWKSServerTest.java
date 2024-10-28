package com.cc.jwks;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Test class for JWKSServer. It tests the server's JWKS and authentication endpoints.
 */
public class JWKSServerTest {

    /**
     * Set up the test environment by starting the JWKSServer.
     * @throws Exception if the server fails to start
     */
    @BeforeClass
    public static void setUp() throws Exception {
        // Start the server before running tests
        JWKSServer.main(new String[]{});
    }

    /**
     * Tear down the test environment. Can include server shutdown if implemented.
     * @throws Exception if the tear down process fails
     */
    @AfterClass

    public static void tearDown() throws Exception {
        
    }

    /**
     * Tests the JWKS endpoint to ensure it returns a 200 status and valid JWKS.
     * @throws Exception if the HTTP request fails
     */
    @Test
    public void testJWKSHandler() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/.well-known/jwks.json"))
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        System.out.println("JWKS Response: " + response.body());
       
    }

    /**
     * Tests the /auth endpoint without the expired query parameter to ensure it handles requests correctly.
     * @throws Exception if the HTTP request fails
     */
    @Test
    public void testAuthHandler() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/auth"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        System.out.println("JWT: " + response.body());
       
    }

    /**
     * Tests the /auth endpoint with the expired query parameter to check how it handles expired keys.
     * @throws Exception if the HTTP request fails
     */
    @Test
    public void testAuthHandlerWithExpiredKey() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/auth?expired=true"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        System.out.println("Expired JWT: " + response.body());
        
    }
}

package io.blindnet.blindnet.internal;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.exception.BlindnetApiException;
import io.blindnet.blindnet.exception.InvalidJwtException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

import static java.util.Objects.requireNonNull;


/**
 * Provides API to for standard HTTP methods.
 */
public class HttpClient {

    private static final String GET_METHOD = "GET";
    private static final String POST_METHOD = "POST";
    private static final String PUT_METHOD = "PUT";
    private static final String DELETE_METHOD = "DELETE";

    private static final int CONNECT_TIMEOUT = 15000;
    private static final int READ_TIMEOUT = 15000;

    /**
     * Private constructor as class implements Singleton pattern.
     */
    private HttpClient() {
    }

    /**
     * Inner class which holds Singleton instance.
     */
    private static class InstanceHolder {
        public static final HttpClient instance = new HttpClient();
    }

    /**
     * Returns Singleton instance of the class.
     *
     * @return Key Storage object.
     */
    public static HttpClient getInstance() {
        return HttpClient.InstanceHolder.instance;
    }

    /**
     * Sends HTTP Post request.
     *
     * @param url         an url of the request.
     * @param jwt         a jwt used for authorization.
     * @param requestBody a body of the request.
     * @return a http response object.
     */
    public HttpResponse post(String url, String jwt, byte[] requestBody) {
        return sendRequest(url, jwt, requestBody, POST_METHOD);
    }

    /**
     * Sends HTTP Put request.
     *
     * @param url         an url of the request.
     * @param jwt         a jwt used for authorization.
     * @param requestBody a body of the request.
     * @return a http response object.
     */
    public HttpResponse put(String url, String jwt, byte[] requestBody) {
        return sendRequest(url, jwt, requestBody, PUT_METHOD);
    }

    /**
     * Sends HTTP Get request.
     *
     * @param url an url of the request.
     * @param jwt a jwt used for authorization.
     * @return a http response object.
     */
    public HttpResponse get(String url, String jwt) {
        requireNonNull(url, "Url cannot be null.");
        requireNonNull(jwt, "JWT cannot be null.");

        HttpURLConnection con = init(url, GET_METHOD);

        con.setRequestProperty("Authorization", "Bearer " + jwt);
        con.setRequestProperty("Accept", "application/json");

        return createResponse(con, url);
    }

    /**
     * Sends HTTP Delete request.
     *
     * @param url an url of the request.
     * @param jwt a jwt used for authorization.
     * @return a http response object.
     */
    public HttpResponse delete(String url, String jwt) {
        requireNonNull(url, "Url cannot be null.");
        requireNonNull(jwt, "JWT cannot be null.");

        HttpURLConnection con = init(url, DELETE_METHOD);

        con.setRequestProperty("Authorization", "Bearer " + jwt);
        con.setRequestProperty("Accept", "application/json");

        return createResponse(con, url);
    }

    /**
     * Sends a HTTP request.
     *
     * @param url         an url of the request.
     * @param jwt         a jwt used for authorization.
     * @param requestBody a body of the request.
     * @param method      a HTTP method.
     * @return a http response object.
     */
    private HttpResponse sendRequest(String url, String jwt, byte[] requestBody, String method) {
        requireNonNull(url, "Url cannot be null.");
        requireNonNull(requestBody, "Request body cannot be null.");

        HttpURLConnection con = init(url, method);
        con.setRequestProperty("Authorization", "Bearer " + jwt);
        con.setRequestProperty("Content-Type", "application/json; utf-8");
        con.setRequestProperty("Accept", "application/json");

        sendRequestBody(con, requestBody);

        return createResponse(con, url);
    }

    /**
     * Sends a body of the request.
     *
     * @param con         a http url connection object.
     * @param requestBody a request body as byte array.
     */
    private void sendRequestBody(HttpURLConnection con, byte[] requestBody) {
        try {
            con.setDoOutput(true);
            try (OutputStream os = con.getOutputStream()) {
                os.write(requestBody, 0, requestBody.length);
            }
        } catch (IOException exception) {
            throw new BlindnetApiException("Error sending request to Blindnet API.");
        }
    }

    /**
     * Creates a response of the request.
     *
     * @param con a http url connection object.
     * @param url an url of the request.
     * @return a http response object.
     */
    private HttpResponse createResponse(HttpURLConnection con, String url) {
        try {
            int responseCode = con.getResponseCode();

            if (responseCode != HttpURLConnection.HTTP_OK && responseCode != HttpURLConnection.HTTP_CREATED) {
                String msg = String.format("Blindnet API response is %d %s for url: %s. Message: %s",
                        responseCode,
                        con.getResponseMessage(),
                        url,
                        con.getErrorStream() != null ? new String(parseResponse(con.getErrorStream())) : "");
                if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
                    throw new InvalidJwtException(msg);
                }

                throw new BlindnetApiException(msg);
            }

            // reading response
            byte[] response = parseResponse(con.getInputStream());
            con.disconnect();

            return new HttpResponse.Builder(responseCode)
                    .withMessage(con.getResponseMessage())
                    .withBody(response)
                    .build();
        } catch (IOException exception) {
            throw new BlindnetApiException("Error parsing response from Blindnet API.");
        }
    }

    /**
     * Parses response of the request.
     *
     * @param inputStream an input stream of the http url connection.
     * @return a response of the request as byte array.
     * @throws IOException an exception thrown if parsing fails.
     */
    private byte[] parseResponse(InputStream inputStream) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        return content.toString().getBytes();
    }


    /**
     * Initialises a http url connection object.
     *
     * @param url    an url of the request.
     * @param method a HTTP method of the request.
     * @return a http url connection object.
     */
    private HttpURLConnection init(String url, String method) {
        try {
            HttpURLConnection con = (HttpURLConnection) (new URL(url)).openConnection();
            con.setRequestMethod(method);
            con.setConnectTimeout(CONNECT_TIMEOUT);
            con.setReadTimeout(READ_TIMEOUT);

            return con;
        } catch (IOException exception) {
            throw new BlindnetApiException("Error while opening a connection to the Blindnet API.");
        }
    }

}

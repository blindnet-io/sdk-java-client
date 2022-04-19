package io.blindnet.blindnet.internal;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.exception.BlindnetApiException;
import io.blindnet.blindnet.exception.InvalidTokenException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

import static java.util.Objects.nonNull;
import static java.util.Objects.requireNonNull;


/**
 * Provides API for sending HTTP requests.
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
     * Sends HTTP POST request.
     *
     * @param url         an url of the request.
     * @param requestBody a body of the request.
     * @return a http response object.
     */
    public HttpResponse post(String url, byte[] requestBody) {
        return sendRequest(url, requestBody, POST_METHOD);
    }

    /**
     * Sends HTTP POST request by streaming body content.
     *
     * @param url         an url of the request.
     * @param requestBody a body of the request, represented as stream.
     * @return a http response object.
     */
    public HttpResponse post(String url, InputStream requestBody) {
        return sendRequest(url, requestBody, POST_METHOD);
    }

    /**
     * Sends HTTP PUT request.
     *
     * @param url         an url of the request.
     * @param requestBody a body of the request.
     * @return a http response object.
     */
    public HttpResponse put(String url, byte[] requestBody) {
        return sendRequest(url, requestBody, PUT_METHOD);
    }

    /**
     * Sends HTTP GET request.
     *
     * @param url an url of the request.
     * @return a http response object.
     */
    public HttpResponse get(String url) {
        requireNonNull(url, "Url cannot be null.");

        HttpURLConnection con = init(url, GET_METHOD);

        con.setRequestProperty("Authorization", "Bearer " + requireNonNull(TokenConfig.INSTANCE.getToken(), "Token not configured properly."));
        con.setRequestProperty("Accept", "application/json");

        return createResponse(con, url);
    }

    /**
     * Sends HTTP GET request and expects response in form of stream.
     *
     * @param url an url of the request.
     * @return a http url connection object.
     */
    public HttpURLConnection getAsStream(String url) {
        requireNonNull(url, "Url cannot be null.");

        HttpURLConnection con = init(url, GET_METHOD);

        con.setRequestProperty("Authorization", "Bearer " + requireNonNull(TokenConfig.INSTANCE.getToken(), "Token not configured properly."));
        con.setRequestProperty("Accept", "application/json");

        validateResponse(con, url);
        return con;
    }

    /**
     * Sends HTTP DELETE request.
     *
     * @param url an url of the request.
     * @return a http response object.
     */
    public HttpResponse delete(String url) {
        requireNonNull(url, "Url cannot be null.");

        HttpURLConnection con = init(url, DELETE_METHOD);

        con.setRequestProperty("Authorization", "Bearer " + requireNonNull(TokenConfig.INSTANCE.getToken(), "Token not configured properly."));
        con.setRequestProperty("Accept", "application/json");

        return createResponse(con, url);
    }

    /**
     * Sends a HTTP request.
     *
     * @param url         an url of the request.
     * @param requestBody a body of the request.
     * @param method      a HTTP method.
     * @return a http response object.
     */
    private HttpResponse sendRequest(String url, byte[] requestBody, String method) {
        requireNonNull(requestBody, "Request body cannot be null.");

        HttpURLConnection con = initSendRequest(url, method);
        sendRequestBody(con, requestBody);
        return createResponse(con, url);
    }

    /**
     * SEnds a HTTP request with a request body in for of stream.
     *
     * @param url         an url of the request.
     * @param requestBody a body of the request, in form of stream.
     * @param method      a HTTP method.
     * @return a http response object.
     */
    private HttpResponse sendRequest(String url, InputStream requestBody, String method) {
        requireNonNull(requestBody, "Request body cannot be null.");

        HttpURLConnection con = initSendRequest(url, method);
        sendRequestBody(con, requestBody);

        return createResponse(con, url);
    }

    /**
     * Creates initial HTTP connection used to send HTTP request.
     *
     * @param url    an url of the request.
     * @param method a HTTP method.
     * @return a http url connection object.
     */
    private HttpURLConnection initSendRequest(String url, String method) {
        requireNonNull(url, "Url cannot be null.");
        requireNonNull(method, "Method cannot be null.");

        HttpURLConnection con = init(url, method);
        con.setRequestProperty("Authorization", "Bearer " + requireNonNull(TokenConfig.INSTANCE.getToken(), "Token not configured properly."));
        con.setRequestProperty("Content-Type", "application/json; utf-8");
        con.setRequestProperty("Accept", "application/json");

        return con;
    }

    /**
     * Writes a body of the request to the request stream.
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
     * Writes a body of the request to the request stream.
     *
     * @param con         a http url connection object.
     * @param requestBody a request body in form of stream.
     */
    private void sendRequestBody(HttpURLConnection con, InputStream requestBody) {
        try {
            con.setDoOutput(true);
            try (OutputStream os = con.getOutputStream()) {
                requestBody.transferTo(os);
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
            int responseCode = validateResponse(con, url);

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
     * Validates response.
     *
     * @param con a http url connection object.
     * @param url an url of the request.
     * @return a http response code.
     */
    private int validateResponse(HttpURLConnection con, String url) {
        try {
            int responseCode = con.getResponseCode();

            if (responseCode != HttpURLConnection.HTTP_OK && responseCode != HttpURLConnection.HTTP_CREATED) {
                String msg = String.format("Blindnet API response is %d %s for url: %s. Message: %s",
                        responseCode,
                        con.getResponseMessage(),
                        url,
                        nonNull(con.getErrorStream()) ? new String(parseResponse(con.getErrorStream())) : "");
                if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
                    throw new InvalidTokenException(msg);
                }

                throw new BlindnetApiException(msg);
            }

            return responseCode;
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

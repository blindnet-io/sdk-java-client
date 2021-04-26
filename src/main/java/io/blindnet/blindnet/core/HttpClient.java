package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.HttpResponse;
import io.blindnet.blindnet.exception.BlindnetApiException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

// todo java doc
/**
 *
 * @author stefanveselinovic
 */
class HttpClient {

    private static final Logger LOGGER = Logger.getLogger(HttpClient.class.getName());

    private static final String GET_METHOD = "GET";
    private static final String POST_METHOD = "POST";
    private static final String DELETE_METHOD = "DELETE";

    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 5000;

    public HttpClient() {}

    public HttpResponse post(String url, String jwt, byte[] body) throws IOException {
        Objects.requireNonNull(url, "Url cannot be null.");
        Objects.requireNonNull(body, "Message body cannot be null.");

        HttpURLConnection con = init(url, POST_METHOD);
        con.setRequestProperty("Authorization","Bearer " + jwt);
        con.setRequestProperty("Content-Type", "application/json; utf-8");
        con.setRequestProperty("Accept", "application/json");

        con.setDoOutput(true);
        try(OutputStream os = con.getOutputStream()) {
            os.write(body, 0, body.length);
        }

        return createResponse(con, url);
    }

    // todo authentication
    public HttpResponse get(String url, String jwt) throws IOException {
        HttpURLConnection con = init(url, GET_METHOD);

        con.setRequestProperty("Authorization","Bearer " + jwt);
        con.setRequestProperty("Accept", "application/json");

        // todo; add params if needed

        return createResponse(con, url);
    }


    private HttpResponse createResponse(HttpURLConnection con, String url) throws IOException {
        int responseCode = con.getResponseCode();

        if (responseCode != HttpURLConnection.HTTP_OK && responseCode != HttpURLConnection.HTTP_CREATED){
            String msg = String.format("Blindnet API response is %d %s  for url: %s.",
                    responseCode,
                    con.getResponseMessage(),
                    url);
            LOGGER.log(Level.SEVERE, msg);
            throw new BlindnetApiException(msg);
        }

        // reading response
        byte[] response = parseResponse(con.getInputStream());
        con.disconnect();

        return new HttpResponse.Builder(responseCode)
                .withMessage(con.getResponseMessage())
                .withBody(response)
                .build();
    }

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
     *
     * @param url
     * @param method
     * @return
     * @throws IOException
     */
    private HttpURLConnection init(String url, String method) throws IOException {
        HttpURLConnection con = (HttpURLConnection) (new URL(url)).openConnection();
        con.setRequestMethod(method);
        con.setConnectTimeout(CONNECT_TIMEOUT);
        con.setReadTimeout(READ_TIMEOUT);

        return con;
    }

}

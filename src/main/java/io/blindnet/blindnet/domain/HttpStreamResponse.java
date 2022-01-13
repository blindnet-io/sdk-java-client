package io.blindnet.blindnet.domain;

import java.io.InputStream;

/**
 * A wrapper class for the http response in form of a stream.
 */
public class HttpStreamResponse {

    /**
     * A status of the response.
     */
    private final int status;

    /**
     * A message of the response.
     */
    private final String message;

    /**
     * A body of the response.
     */
    private final InputStream body;

    private HttpStreamResponse(Builder builder) {
        this.status = builder.status;
        this.message = builder.message;
        this.body = builder.body;
    }

    /**
     * Builder pattern implementation.
     */
    public static class Builder {
        private final int status;
        private String message;
        private InputStream body;

        public Builder(int status) {
            this.status = status;
        }

        public Builder withMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder withBody(InputStream body) {
            this.body = body;
            return this;
        }

        public HttpStreamResponse build() {
            return new HttpStreamResponse(this);
        }
    }

    public int getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public InputStream getBody() {
        return body;
    }

}

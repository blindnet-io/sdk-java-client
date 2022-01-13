package io.blindnet.blindnet.domain;

/**
 * A wrapper class for the http response.
 */
public final class HttpResponse {

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
    private final byte[] body;

    private HttpResponse(Builder builder) {
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
        private byte[] body;

        public Builder(int status) {
            this.status = status;
        }

        public Builder withMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder withBody(byte[] body) {
            this.body = body;
            return this;
        }

        public HttpResponse build() {
            return new HttpResponse(this);
        }
    }

    public int getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public byte[] getBody() {
        return body;
    }

}

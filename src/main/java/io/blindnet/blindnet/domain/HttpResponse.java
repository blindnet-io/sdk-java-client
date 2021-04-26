package io.blindnet.blindnet.domain;

public class HttpResponse {

    private final int status;
    private final String message;
    private final byte[] body;

    private HttpResponse(Builder builder) {
        this.status = builder.status;
        this.message = builder.message;
        this.body = builder.body;
    }

    public static class Builder {
        private int status;
        private String message;
        private byte[] body;

        public Builder(int status) {
            this.status = status;
        }

        public Builder withMessage(String message){
            this.message = message;
            return this;
        }

        public Builder withBody(byte[] body) {
            this.body = body;
            return this;
        }

        public HttpResponse build(){
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

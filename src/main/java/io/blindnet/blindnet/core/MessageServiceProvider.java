package io.blindnet.blindnet.core;

import io.blindnet.blindnet.MessageService;

public class MessageServiceProvider {

    private MessageServiceProvider() {}

    public static MessageService getInstance() {
        return new MessageServiceImpl();
    }

}

package io.blindnet.blindnet.core;

import io.blindnet.blindnet.domain.KeyWrapper;

import java.security.PublicKey;

//todo This class implementation depends on Blindnet REST API
class BlindnetClient {

    // todo; method used in FR-SDK03
    // todo; define return value
    public void register(String jwt, PublicKey encryptionPublicKey, PublicKey signingPublicKey, String signedJwt) {
        System.out.println("Sends register request to blindnet API. Handles the response.");
    }

    // todo; method used in FR-SDK04
    public PublicKey fetchPublicKey(String jwt, int recipientId) {
        System.out.println("Sends request to fetch public key of recipient from blindnet API.");
        return null;
    }

    // todo: FR-SDK05
    // todo; define return value
    public void sendSymmetricKeys(String jwt, KeyWrapper senderKey, KeyWrapper recipientKey) {
        System.out.println("Sends senders and recipients keys to the blindnet API.");
    }

    // todo: FR-SDK06
    // todo; define return value
    public void fetchSymmetricKey(String jwt, int senderId, int recipientId) {
        System.out.println("Sends request to blindnet API to fetch symmetric keys.");
        // Response is an encrypted symmetric key and its signature

        // if user id in jwt == recipientId
        PublicKey publicKey = fetchPublicKey(jwt, recipientId);
        // else use local public key (?)

        // verifies the key signature with the retrieved public key
        SigningService.verify("signature from response", publicKey);

        // decrypts the encrypted symmetric keys with the local private key.
    }

}

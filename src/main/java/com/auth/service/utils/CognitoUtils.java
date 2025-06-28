package com.auth.service.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CognitoUtils {

    public static String calculateSecretHash(String username, String clientId, String clientSecret) {
        try {
            final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
            SecretKeySpec signingKey = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal((username + clientId).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating secret hash", e);
        }
    }

}

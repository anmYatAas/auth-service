package com.auth.service.service;

import com.auth.service.utils.CognitoUtils;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;

@Service
public class CognitoService {

    private final CognitoIdentityProviderClient cognitoClient;

    private final String clientId = "57ctmdq1fmk1cru9ksabq5dr5r";

    private final String clientSecret = "1bne9o4allsa3htsb0rc4h1khe210jfp1a34mf3ses76tmpq284k";

    public CognitoService() {
        this.cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.EU_NORTH_1)
                .build();
    }

    public void signUpUser(String username, String password, String email) {

        String secretHash = CognitoUtils.calculateSecretHash(username, clientId, clientSecret);

        SignUpRequest request = SignUpRequest.builder()
                .clientId(clientId)
                .secretHash(secretHash)
                .username(username)
                .password(password)
                .userAttributes(
                        AttributeType.builder().name("email").value(email).build()
                )
                .build();
        cognitoClient.signUp(request);
    }

    public Map<String, String> loginUser(String username, String password) {

        String secretHash = CognitoUtils.calculateSecretHash(username, clientId, clientSecret);

        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", secretHash);

        InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(clientId)
                .authParameters(authParams)
                .build();

        InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);
        AuthenticationResultType result = authResponse.authenticationResult();

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", result.accessToken());
        tokens.put("id_token", result.idToken());
        tokens.put("refresh_token", result.refreshToken());

        return tokens;
    }
}


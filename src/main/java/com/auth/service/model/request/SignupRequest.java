package com.auth.service.model.request;

import lombok.Data;

@Data
public class SignupRequest {

    private String username;

    private String password;

    private String email;
}

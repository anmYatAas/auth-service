package com.auth.service.model.request;

import lombok.Data;

@Data
public class LoginRequest {

    private String username;

    private String password;
}

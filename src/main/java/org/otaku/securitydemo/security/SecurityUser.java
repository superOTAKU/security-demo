package org.otaku.securitydemo.security;

import lombok.Data;

import java.util.List;

@Data
public class SecurityUser {
    private String id;
    private String username;
    private List<String> authorities;
}

package org.otaku.securitydemo.controller;

import com.auth0.jwt.JWT;
import org.otaku.securitydemo.config.SecurityProperties;
import org.otaku.securitydemo.dto.AccessToken;
import org.otaku.securitydemo.dto.LoginReq;
import org.otaku.securitydemo.security.SecurityUser;
import org.otaku.securitydemo.security.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Validated
@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private SecurityProperties securityProperties;

    @PreAuthorize("permitAll()")
    @PostMapping("/auth")
    public AccessToken login(@RequestBody @Valid LoginReq req) {
        UsernamePasswordAuthenticationToken authenticate = (UsernamePasswordAuthenticationToken)authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
        UserDetailsImpl details = (UserDetailsImpl)authenticate.getPrincipal();
        SecurityUser securityUser = details.getSecurityUser();
        String jwtStr = JWT.create().withClaim("id", securityUser.getId())
                .withClaim("username", securityUser.getUsername())
                .withClaim("authorities", securityUser.getAuthorities())
                .sign(securityProperties.getAlgorithm());
        AccessToken accessToken = new AccessToken();
        accessToken.setToken(jwtStr);
        return accessToken;
    }

}

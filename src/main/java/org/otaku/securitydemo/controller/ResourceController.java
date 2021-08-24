package org.otaku.securitydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/res")
@PreAuthorize("isAuthenticated()")
@RestController
public class ResourceController {

    @GetMapping("/1")
    public String resource1() {
        return "resource1";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @GetMapping("/2")
    public String resource2() {
        return "/resource2";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @GetMapping("/3")
    public String resource3() {
        return "/resource3";
    }

}

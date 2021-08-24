package org.otaku.securitydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@PreAuthorize("permitAll()")
@RequestMapping("/anonymous")
@RestController
public class AnonymousController {

    @GetMapping
    public String hello() {
        return "hello";
    }

}

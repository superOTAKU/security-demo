package org.otaku.securitydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.equals("admin")) {
            SecurityUser securityUser = new SecurityUser();
            securityUser.setId("1");
            securityUser.setUsername("admin");
            securityUser.setAuthorities(List.of("ROLE_ADMIN"));
            return new UserDetailsImpl(securityUser, passwordEncoder.encode("Aa123456"));
        }
        throw new UsernameNotFoundException("user[" + username + "] not found!");
    }

}

package org.otaku.securitydemo.config;

import org.otaku.securitydemo.security.HttpHeaderSecurityContextRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;

import static org.otaku.securitydemo.security.Constants.*;

/**
 * 基于springSecurity的核心机制，进行登录
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private HttpHeaderSecurityContextRepository securityContextRepository;
    @Autowired
    private UserDetailsService userDetailsService;

    public SecurityConfig() {
        //不需要默认的filter
        super(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilter(new WebAsyncManagerIntegrationFilter())
                    .exceptionHandling().accessDeniedHandler(new AccessDeniedHandlerImpl())
                    .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .and()
                    .cors().configurationSource(corsConfigurationSource())
                .and()
                    .headers().frameOptions().disable()
                .and()
                    .securityContext().securityContextRepository(securityContextRepository)
                .and()
                    .anonymous()
                .and()
                    .requestCache()
                .and()
                    .servletApi()
                .and()
                    .authorizeRequests().antMatchers("/**").permitAll();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.singletonList("*"));
        config.setAllowedHeaders(Arrays.asList(AUTHENTICATION_HEADER, HttpHeaders.CONTENT_TYPE));
        config.setAllowCredentials(true);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        config.setExposedHeaders(Collections.singletonList(AUTHENTICATION_HEADER));
        config.setMaxAge(Duration.ofMinutes(30));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}

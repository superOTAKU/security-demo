package org.otaku.securitydemo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.otaku.securitydemo.config.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.List;
import java.util.stream.Collectors;

import static org.otaku.securitydemo.security.Constants.*;

@Component
public class HttpHeaderSecurityContextRepository implements SecurityContextRepository {
    @Autowired
    private SecurityProperties securityProperties;

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        if (!containsContext(requestResponseHolder.getRequest())) {
            return new SecurityContextImpl();
        }
        String jwtToken = requestResponseHolder.getRequest().getHeader(AUTHENTICATION_HEADER);
        DecodedJWT jwt = JWT.require(securityProperties.getAlgorithm()).build().verify(jwtToken);
        Claim idClaim = jwt.getClaim("id");
        Claim authoritiesClaim = jwt.getClaim("authorities");
        List<String> authorities = authoritiesClaim.asList(String.class);
        String id = idClaim.asString();
        SecurityUser securityUser = new SecurityUser();
        securityUser.setId(id);
        securityUser.setUsername(jwt.getClaim("username").asString());
        securityUser.setAuthorities(authorities);
        return new SecurityContextImpl(new PreAuthenticatedAuthenticationToken(securityUser, null,
                authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())));
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        //noop, just retrieve token from header
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return StringUtils.hasText(request.getHeader(AUTHENTICATION_HEADER));
    }
}

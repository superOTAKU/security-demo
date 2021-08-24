package org.otaku.securitydemo.config;

import cn.hutool.crypto.PemUtil;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.Data;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.Assert;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@Configuration
@ConfigurationProperties(prefix = "auth")
public class SecurityProperties implements InitializingBean {
    private String privateKeyPath;
    private String publicKeyPath;
    private Algorithm algorithm;

    @Override
    public void afterPropertiesSet() throws Exception {
        //load key pair
        try (
                var privateKeyIs = new ClassPathResource(privateKeyPath).getInputStream();
                var publicKeyIs = new ClassPathResource(publicKeyPath).getInputStream()
        ) {
            PrivateKey privateKey = PemUtil.readPemPrivateKey(privateKeyIs);
            PublicKey publicKey = PemUtil.readPemPublicKey(publicKeyIs);
            Assert.isInstanceOf(RSAPrivateKey.class, privateKey);
            Assert.isInstanceOf(RSAPublicKey.class, publicKey);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
        }
    }
}

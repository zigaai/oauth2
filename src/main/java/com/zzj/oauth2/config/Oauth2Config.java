package com.zzj.oauth2.config;

import com.google.common.hash.Hashing;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.zzj.oauth2.core.util.strategy.StrategyFactory;
import com.zzj.oauth2.security.keygen.UUIDRefreshTokenGenerator;
import com.zzj.oauth2.security.model.LoginType;
import com.zzj.oauth2.security.model.SecurityProperties;
import com.zzj.oauth2.security.model.SystemUser;
import com.zzj.oauth2.security.processor.LoginProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Configuration
@RequiredArgsConstructor
public class Oauth2Config {

    protected final SecurityProperties securityProperties;

    /**
     * 配置jwk源，使用非对称加密，公开用于检索匹配指定选择器的JWK的方法
     *
     * @return JWKSource
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPairs = securityProperties.getKeyPairs();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPairs.getPublic())
                .privateKey(keyPairs.getPrivate())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 配置jwt解析器
     *
     * @param jwkSource jwk源
     * @return JwtDecoder
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        // Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(Arrays.asList(new JwtTimestampValidator(Duration.of(0, ChronoUnit.SECONDS))
//                , new JwtSaltValidator(saltValidatorStrategy)
        )));
        return decoder;
    }

    /**
     * 添加认证服务器配置，设置jwt签发者、默认端点请求地址等
     *
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

//    /**
//     * 先暂时配置一个基于内存的用户，框架在用户认证时会默认调用
//     * {@link UserDetailsService#loadUserByUsername(String)} 方法根据
//     * 账号查询用户信息，一般是重写该方法实现自己的逻辑
//     *
//     * @param passwordEncoder 密码解析器
//     * @return UserDetailsService
//     */
//    @Bean
//    public UserDetailsService users(PasswordEncoder passwordEncoder) {
//        UserDetails user = User.withUsername("admin")
//                .password(passwordEncoder.encode("123456"))
//                .roles("admin", "normal", "unAuthentication")
//                .authorities("app", "web", "/test2", "/test3")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder,
                                                            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, new UUIDRefreshTokenGenerator());
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JwtClaimsSet.Builder claims = context.getClaims();
            SystemUser systemUser = (SystemUser) context.getPrincipal().getPrincipal();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)
                    || context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                claims.claim("id", systemUser.getId());
                claims.claim("userType", systemUser.getUserType());
                String kid = encryptSalt(systemUser.getUsername(), systemUser.getSalt());
                claims.claim("kid", kid);
                claims.claim("sid", UUID.randomUUID());
                claims.claim("clientId", context.getRegisteredClient().getClientId());
                claims.claim(IdTokenClaimNames.AUTH_TIME, new Date());
            }
        };
    }

    protected String encryptSalt(String username, String salt) {
        return Hashing.sha256().hashString(username + salt, StandardCharsets.UTF_8).toString();
    }

    @Bean
    public StrategyFactory<LoginType, LoginProcessor> loginProcessorStrategy() {
        return new StrategyFactory<>(LoginProcessor.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

package com.zzj.oauth2.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.zzj.oauth2.core.constant.DateTimeConstant;
import com.zzj.oauth2.core.util.JsonUtil;
import com.zzj.oauth2.security.model.Oauth2RegisteredClient;
import com.zzj.oauth2.security.repo.Oauth2RegisteredClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class Oauth2RegisteredClientService implements RegisteredClientRepository {

    private final Oauth2RegisteredClientRepository oauth2RegisteredClientRepository;
    private final RedisTemplate<String, Object> redisTemplate;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String clientId) {
        return findByClientId(clientId);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Oauth2RegisteredClient registeredClient = this.getByClientId(clientId);
        RegisteredClient.Builder builder = RegisteredClient.withId(registeredClient.getClientId())
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt().atZone(DateTimeConstant.UTC_ZONE_ID).toInstant())
                .clientName(registeredClient.getClientName())
                .clientSecret(registeredClient.getClientSecret())

                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(clientAuthenticationMethods ->
                        clientAuthenticationMethods.addAll(
                                StringUtils.commaDelimitedListToSet(registeredClient.getClientAuthenticationMethods()).stream().map(ClientAuthenticationMethod::new).toList()
                        )
                )
                .authorizationGrantTypes(authorizationGrantTypes -> authorizationGrantTypes.addAll(
                        StringUtils.commaDelimitedListToSet(registeredClient.getAuthorizationGrantTypes()).stream().map(AuthorizationGrantType::new).toList()
                ))
                .redirectUris(redirectUris -> redirectUris.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getRedirectUris())))
                .scopes(scopes -> scopes.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getScopes())));
        if (registeredClient.getClientSecretExpiresAt() != null) {
            builder.clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt().atZone(DateTimeConstant.UTC_ZONE_ID).toInstant());
        }
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireProofKey(false)
                .requireAuthorizationConsent(true);
        HashMap<String, Object> clientSettingsMap = null;
        try {
            clientSettingsMap = JsonUtil.readValue(registeredClient.getClientSecret(), HashMap.class);
        } catch (JsonProcessingException e) {
//            throw new IllegalArgumentException("parse clientSettings json error", e);
        }
        if (!CollectionUtils.isEmpty(clientSettingsMap)) {
            clientSettingsMap.forEach((k, v) -> {
                if (v != null) {
                    clientSettingsBuilder.setting(k, v);
                }
            });
        }
//        clientSettingsBuilder.requireAuthorizationConsent(false);
        builder.clientSettings(clientSettingsBuilder.build());
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .accessTokenTimeToLive(Duration.ofHours(1))
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .deviceCodeTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(false)
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);
        HashMap<String, Object> tokenSettingsMap = null;
        try {
            tokenSettingsMap = JsonUtil.getRedisInstance().readValue(registeredClient.getTokenSettings(), HashMap.class);
        } catch (JsonProcessingException e) {
//            throw new IllegalArgumentException("parse tokenSettings json error", e);
        }
        if (!CollectionUtils.isEmpty(tokenSettingsMap)) {
            tokenSettingsMap.forEach((k, v) -> {
                if (v != null) {
                    tokenSettingsBuilder.setting(k, v);
                }
            });
        }
        tokenSettingsBuilder.reuseRefreshTokens(false);
        builder.tokenSettings(tokenSettingsBuilder.build());
        if (StringUtils.hasText(registeredClient.getPostLogoutRedirectUris())) {
            builder.postLogoutRedirectUris(logoutRedirectUris -> logoutRedirectUris.addAll(StringUtils.commaDelimitedListToSet(registeredClient.getPostLogoutRedirectUris())));
        }
        return builder.build();
    }

    public Oauth2RegisteredClient getByClientId(String clientId) {
        String key = "oauth2::client:" + clientId;
        Oauth2RegisteredClient oauth2RegisteredClient = (Oauth2RegisteredClient) redisTemplate.opsForValue().get(key);
        if (oauth2RegisteredClient == null) {
            oauth2RegisteredClient = oauth2RegisteredClientRepository.selectById(clientId);
        }
        if (oauth2RegisteredClient != null) {
            redisTemplate.opsForValue().set(key, oauth2RegisteredClient, 3, TimeUnit.DAYS);
        }
        return oauth2RegisteredClient;
    }

}

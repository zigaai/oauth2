package com.zzj.oauth2.security.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
@ToString
public class RedisOAuth2Authorization implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 主键
     */
    private String id;

    /**
     * 授权申请时使用的客户端id
     */
    private String registeredClientId;

    /**
     * 授权用户姓名
     */
    private String principalName;

    /**
     * 授权申请时使用 grant_type
     */
    private String authorizationGrantType;

    /**
     * 授权申请的scope
     */
    private String authorizedScopes;

    /**
     * 授权的认证信息(当前用户)、请求信息(授权申请请求)
     */
    private String attributes;

    /**
     * 授权申请时的state
     */
    private String state;

    /**
     * 授权码的值
     */
    private String authorizationCodeValue;

    /**
     * 授权码签发时间
     */
    private Instant authorizationCodeIssuedAt;

    /**
     * 授权码过期时间
     */
    private Instant authorizationCodeExpiresAt;

    /**
     * 授权码元数据
     */
    private String authorizationCodeMetadata;

    /**
     * access token的值
     */
    private String accessTokenValue;

    /**
     * access token签发时间
     */
    private Instant accessTokenIssuedAt;

    /**
     * access token过期时间
     */
    private Instant accessTokenExpiresAt;

    /**
     * access token元数据
     */
    private String accessTokenMetadata;

    /**
     * access token的类型
     */
    private String accessTokenType;

    /**
     * access token中包含的scope
     */
    private String accessTokenScopes;

    /**
     * refresh token的值
     */
    private String refreshTokenValue;

    /**
     * refresh token签发使劲
     */
    private Instant refreshTokenIssuedAt;

    /**
     * refresh token过期时间
     */
    private Instant refreshTokenExpiresAt;

    /**
     * refresh token元数据
     */
    private String refreshTokenMetadata;

    /**
     * id token的值
     */
    private String oidcIdTokenValue;

    /**
     * id token签发时间
     */
    private Instant oidcIdTokenIssuedAt;

    /**
     * id token过期时间
     */
    private Instant oidcIdTokenExpiresAt;

    /**
     * id token元数据
     */
    private String oidcIdTokenMetadata;

    /**
     * id token中包含的属性
     */
    private String oidcIdTokenClaims;

    /**
     * 用户码的值
     */
    private String userCodeValue;

    /**
     * 用户码签发时间
     */
    private Instant userCodeIssuedAt;

    /**
     * 用户码过期时间
     */
    private Instant userCodeExpiresAt;

    /**
     * 用户码元数据
     */
    private String userCodeMetadata;

    /**
     * 设备码的值
     */
    private String deviceCodeValue;

    /**
     * 设备码签发时间
     */
    private Instant deviceCodeIssuedAt;

    /**
     * 设备码过期时间
     */
    private Instant deviceCodeExpiresAt;

    /**
     * 设备码元数据
     */
    private String deviceCodeMetadata;

    /**
     * 当前对象在Redis中的过期时间
     */
    private Long timeout;

}

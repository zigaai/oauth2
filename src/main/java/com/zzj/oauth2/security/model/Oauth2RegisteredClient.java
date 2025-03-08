package com.zzj.oauth2.security.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@TableName("oauth2_registered_client")
public class Oauth2RegisteredClient implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 客户端ID
     */
    @TableId(type = IdType.INPUT)
    private String clientId;

    private LocalDateTime clientIdIssuedAt;

    /**
     * 客户端密钥
     */
    private String clientSecret;

    private LocalDateTime clientSecretExpiresAt;

    /**
     * 客户端名称
     */
    private String clientName;

    /**
     * 认证方式, 多个,隔开: client_secret_basic
     */
    private String clientAuthenticationMethods;

    /**
     * 授权方式, 多个,隔开: 授权码: authorization_code
     */
    private String authorizationGrantTypes;

    /**
     * 回调地址, 多个,隔开
     */
    private String redirectUris;

    /**
     * 作用域, 多个,隔开
     */
    private String scopes;

    /**
     * 客户端配置
     */
    private String clientSettings;

    /**
     * token相关配置
     */
    private String tokenSettings;

    private String postLogoutRedirectUris;
}

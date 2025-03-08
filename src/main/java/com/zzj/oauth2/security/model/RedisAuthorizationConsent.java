package com.zzj.oauth2.security.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
public class RedisAuthorizationConsent implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 当前授权确认的客户端id
     */
    private String registeredClientId;

    /**
     * 当前授权确认用户的 username
     */
    private String principalName;

    /**
     * 授权确认的scope
     */
    private String authorities;

}

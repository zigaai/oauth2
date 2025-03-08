package com.zzj.oauth2.security.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@ToString
@RequiredArgsConstructor
public class UPMSToken implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * access token
     */
    private final String accessToken;

    /**
     * 签发时间
     */
    private final Long iat;

    /**
     * 过期时间
     */
    private final Long exp;

    /**
     * access token 过期时间/秒
     */
    private final long expiresIn;

}

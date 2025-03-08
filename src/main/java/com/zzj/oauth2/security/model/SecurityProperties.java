package com.zzj.oauth2.security.model;

import com.zzj.oauth2.core.util.SecurityUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.KeyPair;
import java.util.Set;

@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    /**
     * 忽略鉴权路径
     */
    private Set<String> ignoreUrls;

    /**
     * token过期时间/s
     */
    private Long timeToLive = 3600L;

    /**
     * RSA配置
     */
    private RSA rsa;

    /**
     * RSA非对称密钥
     */
    @Getter
    @Setter
    @ToString
    public static class RSA {

        /**
         * 公钥
         */
        private String publicKey;

        /**
         * 私钥
         */
        private String privateKey;

        private KeyPair keyPair;
    }

    public KeyPair getKeyPairs() {
        if (StringUtils.isBlank(this.rsa.privateKey) || StringUtils.isBlank(this.rsa.publicKey)) {
            return null;
        }
        if (this.rsa.keyPair != null) {
            return this.rsa.keyPair;
        }
        try {
            this.rsa.keyPair = new KeyPair(SecurityUtil.loadPublicKey(this.rsa.publicKey), SecurityUtil.loadPrivateKey(this.rsa.privateKey));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return this.rsa.keyPair;
    }
}

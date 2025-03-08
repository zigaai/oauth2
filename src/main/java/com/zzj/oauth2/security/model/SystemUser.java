package com.zzj.oauth2.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;

@Setter
@Getter
@ToString
public class SystemUser implements UserDetails, Serializable {
    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    /**
     * id
     */
    private Integer id;

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码
     */
    private String password;

    /**
     * token盐值
     */
    @JsonIgnore
    private String salt;

    /**
     * 状态: 0: 正常, 1: 删除
     */
    private Boolean isDeleted;

    /**
     * 用户类型
     */
    private String userType;

    /**
     * 权限
     */
    @JsonIgnore
    private Collection<? extends GrantedAuthority> authorities;

    /**
     * 授权客户端ID
     */
    private String clientId;

    /**
     * JWT接收对象
     */
    private Collection<String> aud;

    /**
     * 授权客户端scope
     */
    private Collection<String> scope;

    @Override
    public boolean isEnabled() {
        return this.isDeleted != null && !this.isDeleted;
    }
}

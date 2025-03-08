package com.zzj.oauth2.security.processor.usernamepassword;

import com.zzj.oauth2.security.model.UserType;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Setter
@Getter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SysUsernamePasswordToken extends UsernamePasswordAuthenticationToken {

    private UserType userType;

    private SysUsernamePasswordToken(Object username, Object password, UserType userType) {
        super(username, password);
        this.userType = userType;
    }

    private SysUsernamePasswordToken(Object username, Object password, UserType userType,
                                     Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userType = userType;
    }

    public static SysUsernamePasswordToken unauthenticated(Object username, Object password, UserType userType) {
        return new SysUsernamePasswordToken(username, password, userType);
    }

    public static SysUsernamePasswordToken authenticated(Object username, Object password, UserType userType, Collection<? extends GrantedAuthority> authorities) {
        return new SysUsernamePasswordToken(username, password, userType, authorities);
    }

}

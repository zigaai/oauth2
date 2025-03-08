package com.zzj.oauth2.security.service;

import com.zzj.oauth2.security.model.SystemUser;
import com.zzj.oauth2.security.model.UserType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class AdminUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SystemUser systemUser = new SystemUser();
        systemUser.setId(1);
        systemUser.setUsername("admin");
        systemUser.setUserType(UserType.ADMIN.name());
        systemUser.setPassword(passwordEncoder.encode("123456"));
        systemUser.setAuthorities(
                Arrays.asList(
                        new SimpleGrantedAuthority("app"),
                        new SimpleGrantedAuthority("normal"),
                        new SimpleGrantedAuthority("/test2"),
                        new SimpleGrantedAuthority("/test3"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                )
        );
        systemUser.setIsDeleted(false);
        return systemUser;
    }
}

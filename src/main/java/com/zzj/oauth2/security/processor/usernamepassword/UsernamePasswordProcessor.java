package com.zzj.oauth2.security.processor.usernamepassword;

import com.zzj.oauth2.security.exception.LoginException;
import com.zzj.oauth2.security.model.LoginParams;
import com.zzj.oauth2.security.model.LoginType;
import com.zzj.oauth2.security.model.SecurityProperties;
import com.zzj.oauth2.security.model.UserType;
import com.zzj.oauth2.security.processor.LoginProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class UsernamePasswordProcessor implements LoginProcessor {

    private final SecurityProperties securityProperties;

    @Override
    public LoginType getKey() {
        return LoginType.USERNAME_PASSWORD;
    }


    @Override
    public Authentication buildUnauthenticated(LoginParams params) {
        params.validateByUsernamePassword();
        String originPass;
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(params.getPassword());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, securityProperties.getKeyPairs().getPrivate());

            originPass = new String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new LoginException("密码解密错误");
        }
        return SysUsernamePasswordToken.unauthenticated(params.getUsername(), originPass, UserType.valueOf(params.getUserType()));
    }
}

package com.zzj.oauth2.security.processor;

import com.zzj.oauth2.core.util.strategy.Strategy;
import com.zzj.oauth2.security.model.LoginParams;
import com.zzj.oauth2.security.model.LoginType;
import org.springframework.security.core.Authentication;

public interface LoginProcessor extends Strategy<LoginType> {

    Authentication buildUnauthenticated(LoginParams params);

}

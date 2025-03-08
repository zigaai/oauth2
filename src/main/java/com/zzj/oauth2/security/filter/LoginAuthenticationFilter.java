package com.zzj.oauth2.security.filter;

import com.nimbusds.jose.JOSEException;
import com.zzj.oauth2.core.module.Res;
import com.zzj.oauth2.core.module.ResponseState;
import com.zzj.oauth2.core.util.JWTUtil;
import com.zzj.oauth2.core.util.strategy.StrategyFactory;
import com.zzj.oauth2.security.exception.LoginException;
import com.zzj.oauth2.security.exception.LoginIllegalArgumentException;
import com.zzj.oauth2.security.model.*;
import com.zzj.oauth2.security.processor.LoginProcessor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");

    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;
    private final StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy;
    private final SecurityProperties securityProperties;

    public LoginAuthenticationFilter(StrategyFactory<LoginType, LoginProcessor> loginTypeLoginProcessorStrategy,
                                     AuthenticationManager authenticationManager,
                                     SecurityProperties securityProperties,
                                     MappingJackson2HttpMessageConverter jackson2HttpMessageConverter) {
        super(LOGIN_REQUEST_MATCHER);
        super.setAuthenticationManager(authenticationManager);
        this.loginTypeLoginProcessorStrategy = loginTypeLoginProcessorStrategy;
        this.securityProperties = securityProperties;
        this.jackson2HttpMessageConverter = jackson2HttpMessageConverter;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        LoginParams params = (LoginParams) jackson2HttpMessageConverter.read(LoginParams.class, new ServletServerHttpRequest(request));
        // TODO tenant 租户 //NOSONAR
        LoginType loginType = LoginType.getByVal(params.getLoginType());
        LoginProcessor processor = loginTypeLoginProcessorStrategy.getStrategy(loginType);
        if (processor == null) {
            throw new LoginIllegalArgumentException("不支持此登录类型登录");
        }
        Authentication unauthenticated = processor.buildUnauthenticated(params);
        return this.getAuthenticationManager().authenticate(unauthenticated);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        SystemUser systemUser = (SystemUser) authResult.getPrincipal();
        PayloadDTO payload = new PayloadDTO();
        payload.setUsername(systemUser.getUsername());
        payload.setId(systemUser.getId());
        payload.setUserType(systemUser.getUserType());
        payload.setExpiresIn(securityProperties.getTimeToLive());
        UPMSToken upmsToken;
        try {
            upmsToken = JWTUtil.generateToken(payload, securityProperties.getKeyPairs());
        } catch (JOSEException e) {
            log.error("生成token错误: ", e);
            jackson2HttpMessageConverter.write(Res.unknownError("生成token错误"), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
            return;
        }
        jackson2HttpMessageConverter.write(Res.success("登录成功", upmsToken), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        String msg = ResponseState.UNKNOWN_ERROR.getMsg();
        if (failed instanceof LoginIllegalArgumentException
                || failed instanceof BadCredentialsException
                || failed instanceof UsernameNotFoundException
                || failed instanceof LoginException) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            msg = failed.getMessage();
        }
        if (failed instanceof DisabledException) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            msg = failed.getMessage();
        }
        jackson2HttpMessageConverter.write(Res.badRequest(msg), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }
}

package com.zzj.oauth2.security.config;

import com.zzj.oauth2.security.filter.JwtFilter;
import com.zzj.oauth2.security.handler.*;
import com.zzj.oauth2.security.keygen.UUIDAuthorizationCodeGenerator;
import com.zzj.oauth2.security.model.SecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    public static final String CONSENT_PAGE_URI = "http://localhost:/consent";

    private final SecurityProperties securityProperties;
    private final UserDetailsService userDetailsService;
    private final DefaultAccessDeniedHandler defaultAccessDeniedHandler;
    private final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;
    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;

    /**
     * 配置端点的过滤器链
     *
     * @param http spring security核心配置类
     * @return 过滤器链
     * @throws Exception 抛出
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 配置默认的设置，忽略认证端点的csrf校验
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // 开启OpenID Connect 1.0协议相关端点
                .oidc(Customizer.withDefaults())
                // 设置自定义用户确认授权页
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .consentPage(CONSENT_PAGE_URI)
                        .errorResponseHandler(new ConsentAuthenticationFailureHandler(jackson2HttpMessageConverter))
                        .authorizationResponseHandler(new ConsentAuthorizationResponseHandler(jackson2HttpMessageConverter))
                        .authenticationProviders(list -> list.forEach(p -> {
                            if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider provider) {
                                provider.setAuthorizationCodeGenerator(new UUIDAuthorizationCodeGenerator());
                            } else if (p instanceof OAuth2AuthorizationConsentAuthenticationProvider provider) {
                                provider.setAuthorizationCodeGenerator(new UUIDAuthorizationCodeGenerator());
                            }
                        }))
                )
                .tokenEndpoint(e -> e.accessTokenResponseHandler(new OAuth2AuthenticationSuccessHandler(jackson2HttpMessageConverter)));
        http
                // 当未登录时访问认证端点时重定向至login页面
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .anonymous(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                );
        http.addFilterAfter(new JwtFilter(securityProperties, userDetailsService), SecurityContextHolderFilter.class);
        return http.build();
    }
}

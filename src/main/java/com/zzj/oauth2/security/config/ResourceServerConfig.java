package com.zzj.oauth2.security.config;

import com.zzj.oauth2.core.util.strategy.StrategyFactory;
import com.zzj.oauth2.security.filter.JwtFilter;
import com.zzj.oauth2.security.filter.LoginAuthenticationFilter;
import com.zzj.oauth2.security.handler.DefaultAccessDeniedHandler;
import com.zzj.oauth2.security.handler.DefaultAuthenticationEntryPoint;
import com.zzj.oauth2.security.model.LoginType;
import com.zzj.oauth2.security.model.SecurityProperties;
import com.zzj.oauth2.security.processor.LoginProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(SecurityProperties.class)
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class ResourceServerConfig {

    private final SecurityProperties properties;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final StrategyFactory<LoginType, LoginProcessor> loginProcessorStrategy;
    private final MappingJackson2HttpMessageConverter jackson2HttpMessageConverter;
    private final DefaultAccessDeniedHandler defaultAccessDeniedHandler;
    private final DefaultAuthenticationEntryPoint defaultAuthenticationEntryPoint;

    /**
     * 配置认证相关的过滤器链
     *
     * @param http spring security核心配置类
     * @return 过滤器链
     * @throws Exception 抛出
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                        // 放行静态资源
                        .requestMatchers(properties.getIgnoreUrls().toArray(new String[]{}))
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                // 指定登录页面
                .anonymous(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .exceptionHandling(c -> c
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler))
                .oauth2ResourceServer(c -> c
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(defaultAuthenticationEntryPoint)
                        .accessDeniedHandler(defaultAccessDeniedHandler)
                );
        postProcessAfterInitialization(http);
        http.addFilterAfter(new JwtFilter(properties, userDetailsService), SecurityContextHolderFilter.class);
        return http.build();
    }

    protected void postProcessAfterInitialization(HttpSecurity http) {
        LoginAuthenticationFilter loginAuthenticationFilter = buildLoginFilter();
        http.addFilterAfter(loginAuthenticationFilter, HeaderWriterFilter.class);
    }

    public LoginAuthenticationFilter buildLoginFilter() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider(passwordEncoder);
        authenticationProvider.setUserDetailsService(userDetailsService);
        return new LoginAuthenticationFilter(loginProcessorStrategy,
                new ProviderManager(authenticationProvider),
                properties,
                jackson2HttpMessageConverter);
    }

}

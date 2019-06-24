package com.melardev.spring.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;

@Configuration
@EnableResourceServer
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint oauthEntryPoint;

    @Autowired
    private OAuthAccessDeniedHandler oauthAccessDeniedHandler;

    // If the Resource Server was a different server we would expose many beans we already exposed in AuthorizationServer
    // such as the token store or the JwtAccessConverter, but since we are on the same server, we skip this because
    // we have already done so.

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .anonymous().disable()
                .authorizeRequests()
                .antMatchers("/dummy/**").authenticated()
                .and().exceptionHandling()
                .authenticationEntryPoint(oauthEntryPoint)
                .accessDeniedHandler(oauthAccessDeniedHandler);
    }

}
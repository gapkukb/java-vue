package com.example.config;


import com.example.entity.vo.response.AuthorizeVO;
import com.example.fliter.JWTAuthorizeFilter;
import com.example.util.JSONResponse;
import com.example.util.JWTUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {
    @Resource
    JWTUtil jwtUtil;

    @Resource
    JWTAuthorizeFilter jwtAuthorizeFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.

            authorizeHttpRequests(config -> {
                config.requestMatchers("/api/auth/**").permitAll().anyRequest().authenticated();
            }).formLogin(config -> {
                config.loginProcessingUrl("/api/auth/login").successHandler(this::onAuthenticationSuccess).failureHandler(this::onAuthenticationFailure);
            }).logout(config -> {
                config.logoutUrl("/logout").logoutSuccessHandler(this::onLogoutSuccess);
            }).exceptionHandling(config -> {
                config.authenticationEntryPoint(this::onUnauthorized).accessDeniedHandler(this::onAccessDenied);
            }).csrf(AbstractHttpConfigurer::disable).sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).addFilterBefore(
                jwtAuthorizeFilter,
                UsernamePasswordAuthenticationFilter.class
            ).build();
    }

    private void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");

        User user = (User) authentication.getPrincipal();
        var vo = new AuthorizeVO();
        String token = jwtUtil.encode(user, 1, "小明");
        vo.setExpire(jwtUtil.expiresAt()).setRole("").setToken(token).setUsername("小明");


        response.getWriter().write(JSONResponse.success(vo).toJSONString());

    }

    private void onAuthenticationFailure(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException exception
    ) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");

        response.getWriter().write(JSONResponse.fail(exception.getMessage()).toJSONString());
    }

    private void onLogoutSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication

    ) throws IOException, ServletException {

        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(JSONResponse.success().toJSONString());
    }

    public void onUnauthorized(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException
    ) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        response.setStatus(401);
//        response.getWriter().write(JSONResponse.fail(401).toJSONString());
    }

    public void onAccessDenied(
        HttpServletRequest request,
        HttpServletResponse response,
        AccessDeniedException accessDeniedException
    ) {
        response.setContentType("application/json;charset=utf-8");
        response.setStatus(403);
    }
}

package com.hht.jwt.Config;

import com.hht.jwt.entity.RestBean;
import com.hht.jwt.filter.JwtAuthentication;
import com.hht.jwt.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author 何鸿涛
 * @date 2024/11/2 下午5:09
 */
public class SecurityConfiguration {

    /**
     * 配置Spring SecurityFilterChain
     * @param http
     * @return
     * @throws Exception
     */

    @Resource
    JwtUtils utils;

    @Resource
    JwtAuthentication jwtAuthentication;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**", "/error").permitAll()
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .anyRequest().hasAnyRole("user")
                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .failureHandler(this::handleProcess)//失败之后返回什么数据
                        .successHandler(this::handleProcess)//成功之后返回什么数据
                        .permitAll()//允许所有用户访问
                )
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .exceptionHandling(conf -> conf
                        //权限不足
                        .accessDeniedHandler(this::handleProcess)
                        //没有登录
                        .authenticationEntryPoint(this::handleProcess)
                )
                //禁用CSRF
                .csrf(AbstractHttpConfigurer::disable)
                //无状态
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .addFilterBefore(jwtAuthentication, UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(jwtAuthenticationFilter, RequestLogFilter.class)
                .build();
    }

    private void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        String authorization = request.getHeader("Authorization");
        if(utils.invalidJwt(authorization)){
            writer.write(RestBean.success("退出成功").asJsonString());
            return;
        }
        RestBean.failure(400,"退出登录失败");
    }

    private void handleProcess(HttpServletRequest request,
                               HttpServletResponse response,
                               Object exceptionOrAuthentication) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        //未登录拦截/无权限
         if(exceptionOrAuthentication instanceof Authentication authentication){
            User user = (User) authentication.getPrincipal();
            String jwt = utils.createJwt(user, "hht", 1);
            writer.write(RestBean.success(jwt).asJsonString());
        }
    }
}



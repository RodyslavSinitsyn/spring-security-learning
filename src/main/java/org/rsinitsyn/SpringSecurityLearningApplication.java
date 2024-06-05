package org.rsinitsyn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
@SpringBootApplication
public class SpringSecurityLearningApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityLearningApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(config ->
                        config.requestMatchers("/public/**").permitAll()
                                .anyRequest().authenticated())
                .exceptionHandling(config -> config.authenticationEntryPoint(redirect403AuthEntryPoint()))
                .build();
    }

    private AuthenticationEntryPoint redirect403AuthEntryPoint() {
        return (request, response, authException) -> {
            response.sendRedirect("http://localhost:8888/public/403.html");
        };
    }

    private AuthenticationEntryPoint unauthorizedAuthEntryPoint() {
        return (request, response, authException) -> {
            authException.printStackTrace();
            response.sendError(HttpStatus.UNAUTHORIZED.value());
        };
    }
}

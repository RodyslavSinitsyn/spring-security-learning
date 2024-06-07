package org.rsinitsyn;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity(debug = true)
@SpringBootApplication
public class SpringSecurityLearningApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityLearningApplication.class, args);
    }


    @Bean
    public JwtAuthenticationConfigurer jwtAuthenticationConfigurer(@Value("${jwt.access-token-key}") String jwtAccessTokenKey,
                                                                   @Value("${jwt.refresh-token-key}") String jwtRefreshTokenKey) {
        return new JwtAuthenticationConfigurer(jwtAccessTokenKey, jwtRefreshTokenKey);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationConfigurer jwtAuthenticationConfigurer) throws Exception {
        return http
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(config -> config
                        .requestMatchers("/error", "/public/**").permitAll()
                        .requestMatchers("/manager.html").hasRole("MANAGER")
                        .anyRequest().authenticated())
                .with(jwtAuthenticationConfigurer, Customizer.withDefaults())
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user"))
                        .roles("USER")
                        .build(),

                User.builder()
                        .username("manager")
                        .password(passwordEncoder().encode("manager"))
                        .roles("MANAGER")
                        .build(),

                User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin"))
                        .roles("ADMIN", "MANAGER")
                        .build()
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

package org.rsinitsyn;

import jakarta.servlet.DispatcherType;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.JdkRegexpMethodPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;

@Configuration
public class SecurityConfig {

    /**
     * Example of all authorization mechanisms.
     *
     * @see org.springframework.security.web.util.matcher.RequestMatcher
     *
     * <b>Order matters!</b>
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(config -> config
                        .requestMatchers("/permit-all").permitAll()
                        .requestMatchers("/deny-all").denyAll()
                        .requestMatchers("/anonymous").anonymous()
                        .requestMatchers("/authenticated").authenticated()
                        .requestMatchers("/remember-me").rememberMe()
                        .requestMatchers("/fully-authenticated").fullyAuthenticated()
                        .requestMatchers("/has-view-authority").hasAuthority("view")
                        .requestMatchers("/has-update-or-delete-authority").hasAnyAuthority("update", "delete")
                        .requestMatchers("/has-admin-role").hasRole("ADMIN")
                        .requestMatchers("/has-customer-or-manager-role").hasAnyRole("CUSTOMER", "MANAGER")
                        .requestMatchers("/has-access").access((authentication, object) -> new AuthorizationDecision(!"rsinitsyn".equals(authentication.get().getName())))
                        .requestMatchers("/{id}").access(new WebExpressionAuthorizationManager("#id == 777"))
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        .requestMatchers("/api/**", "/soap/*").authenticated() // api/v1/users | /soap/getUsers
                )
                .build();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor protectLogTodoMethodPointcut() {
        var pointcut = new JdkRegexpMethodPointcut();
        pointcut.setPattern("org.rsinitsyn.TodoService.logTodo()");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, hasRole("OBSERVER_USER"));
    }

    public RoleHierarchyImpl roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("""
                MANAGER > VERIFIED_USER
                delete_todos > create_todos
                create_todos > view_todos
                """);
    }
}

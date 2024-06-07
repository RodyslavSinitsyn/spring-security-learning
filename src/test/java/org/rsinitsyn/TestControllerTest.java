package org.rsinitsyn;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TestControllerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setup(final ApplicationContext applicationContext) throws Exception {
        this.mockMvc = applicationContext.getBean(MockMvc.class);
    }

    @Test
    void testPermitAll() throws Exception {
        mockMvc.perform(get("/permit-all"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/permit-all")
                        .with(user("radik")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/permit-all")
                        .with(authentication(getRememberMeAuthenticationToken())))
                .andExpect(status().isOk());
    }

    private RememberMeAuthenticationToken getRememberMeAuthenticationToken() {
        return new RememberMeAuthenticationToken(
                UUID.randomUUID().toString(),
                User.builder().username("radik").password("{noop}password").roles("USER").build(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Test
    void testHasViewAuthority() throws Exception {
        mockMvc.perform(get("/has-view-authority"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/has-view-authority")
                        .with(user("radik")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/has-view-authority")
                        .with(user("radik").authorities(new SimpleGrantedAuthority("view"))))
                .andExpect(status().isOk());
    }

    @Test
    void testDenyAll() throws Exception {
        mockMvc.perform(get("/deny-all"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithAnonymousUser
    void testAnonymous() throws Exception {
        mockMvc.perform(get("/anonymous"))
                .andExpect(status().isOk())
                .andExpect(content().string("anonymous"));
    }

    @Test
    @WithMockUser
    void testAuthenticated() throws Exception {
        mockMvc.perform(get("/authenticated"))
                .andExpect(status().isOk())
                .andExpect(content().string("authenticated"));
    }

    @Test
    @WithMockUser
    void testFullyAuthenticated() throws Exception {
        mockMvc.perform(get("/fully-authenticated"))
                .andExpect(status().isOk())
                .andExpect(content().string("fully-authenticated"));
    }

    @Test
    @WithMockUser(authorities = {"update", "delete"})
    void testHasUpdateOrDeleteAuthority() throws Exception {
        mockMvc.perform(get("/has-update-or-delete-authority"))
                .andExpect(status().isOk())
                .andExpect(content().string("has-update-or-delete-authority"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void testHasAdminRole() throws Exception {
        mockMvc.perform(get("/has-admin-role"))
                .andExpect(status().isOk())
                .andExpect(content().string("has-admin-role"));
    }

    @Test
    @WithMockUser(roles = {"CUSTOMER", "MANAGER"})
    void testHasCustomerOrManagerRole() throws Exception {
        mockMvc.perform(get("/has-customer-or-manager-role"))
                .andExpect(status().isOk())
                .andExpect(content().string("has-customer-or-manager-role"));
    }

    @Test
    void testHasAccess() throws Exception {
        mockMvc.perform(get("/has-access").with(user("rsinitsyn")))
                .andExpect(status().isForbidden());
    }

    @Test
    @Disabled
    public void testRememberMe() throws Exception {
        // Simulate the remember-me cookie
        Cookie rememberMeCookie = new Cookie("remember-me", "test-remember-me-token");
        rememberMeCookie.setPath("/");
        rememberMeCookie.setMaxAge(60 * 60 * 24 * 14); // 14 days

        mockMvc.perform(get("/remember-me").cookie(rememberMeCookie))
                .andExpect(status().isOk())
                .andExpect(content().string("remember-me"));
    }
}
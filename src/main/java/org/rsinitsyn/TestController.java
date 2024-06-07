package org.rsinitsyn;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @RequestMapping("/permit-all")
    public ResponseEntity<String> permitAll() {
        return ResponseEntity.ok("permit-all");
    }

    @RequestMapping("/deny-all")
    public ResponseEntity<String> denyAll() {
        return ResponseEntity.ok("deny-all");
    }

    @RequestMapping("/anonymous")
    public ResponseEntity<String> anonymous() {
        return ResponseEntity.ok("anonymous");
    }

    @RequestMapping("/authenticated")
    public ResponseEntity<String> authenticated() {
        return ResponseEntity.ok("authenticated");
    }

    @RequestMapping("/remember-me")
    public ResponseEntity<String> rememberMe() {
        return ResponseEntity.ok("remember-me");
    }

    @RequestMapping("/fully-authenticated")
    public ResponseEntity<String> fullyAuthenticated() {
        return ResponseEntity.ok("fully-authenticated");
    }

    @RequestMapping("/has-view-authority")
    public ResponseEntity<String> hasViewAuthority() {
        return ResponseEntity.ok("has-view-authority");
    }

    @RequestMapping("/has-update-or-delete-authority")
    public ResponseEntity<String> hasUpdateOrDeleteAuthority() {
        return ResponseEntity.ok("has-update-or-delete-authority");
    }

    @RequestMapping("/has-admin-role")
    public ResponseEntity<String> hasAdminRole() {
        return ResponseEntity.ok("has-admin-role");
    }

    @RequestMapping("/has-customer-or-manager-role")
    public ResponseEntity<String> hasCustomerOrManagerRole() {
        return ResponseEntity.ok("has-customer-or-manager-role");
    }

    @RequestMapping("/has-access")
    public ResponseEntity<String> hasAccess() {
        return ResponseEntity.ok("has-access");
    }
}

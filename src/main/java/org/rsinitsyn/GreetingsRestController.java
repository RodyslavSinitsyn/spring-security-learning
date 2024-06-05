package org.rsinitsyn;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class GreetingsRestController {

    @GetMapping("/api/v1/greetings")
    public ResponseEntity<Map<String, String>> greetingsV1() {
        var userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return buildGreetingsResponse(userDetails.getUsername());
    }

    @GetMapping("/api/v2/greetings")
    public ResponseEntity<Map<String, String>> greetingsV2(HttpServletRequest request) {
        Authentication authentication = (Authentication) request.getUserPrincipal();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return buildGreetingsResponse(userDetails.getUsername());
    }

    @GetMapping("/api/v3/greetings")
    public ResponseEntity<Map<String, String>> greetingsV3(@AuthenticationPrincipal UserDetails userDetails) {
        return buildGreetingsResponse(userDetails.getUsername());
    }

    @GetMapping("/api/v4/greetings")
    public ResponseEntity<Map<String, String>> greetingsV4(Principal principal) {
        return buildGreetingsResponse(principal.getName());
    }

    private static ResponseEntity<Map<String, String>> buildGreetingsResponse(String username) {
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("message", "Hello %s!".formatted(username)));
    }
}

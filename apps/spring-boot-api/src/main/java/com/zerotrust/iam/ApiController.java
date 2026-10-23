package com.zerotrust.iam;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> publicInfo() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("service", "spring-boot-resource-server");
        resp.put("status", "ONLINE");
        resp.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/secure/user-profile")
    public ResponseEntity<Map<String, Object>> secureUserProfile(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("username", jwt.getClaimAsString("preferred_username"));
        resp.put("email", jwt.getClaimAsString("email"));
        resp.put("department", jwt.getClaimAsString("department"));
        resp.put("clearance_level", jwt.getClaim("clearance_level"));
        resp.put("roles", jwt.getClaim("realm_access"));
        resp.put("issuer", jwt.getIssuer().toString());
        resp.put("subject", jwt.getSubject());
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/admin/security-metrics")
    @PreAuthorize("hasRole('admin') or hasRole('sec-ops')")
    public ResponseEntity<Map<String, Object>> adminMetrics(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("status", "AUTHORIZED");
        resp.put("operator", jwt.getClaimAsString("preferred_username"));
        resp.put("metric_active_sessions", 142);
        resp.put("mfa_compliance_rate", "99.4%");
        resp.put("threat_detections_last_24h", 0);
        return ResponseEntity.ok(resp);
    }
}

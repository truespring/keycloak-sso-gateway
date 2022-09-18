package club.menofsillim.sso.auth.controller;

import club.menofsillim.sso.auth.entity.KeycloakAccessTokenDTO;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.net.http.HttpHeaders;

@Slf4j
@RestController
public class SampleController {

    @GetMapping("/")
    public String defaultPath() {
        return "default Path!!";
    }

    @GetMapping("/manager/path1")
    public String manager() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        KeycloakPrincipal principal = (KeycloakPrincipal) auth.getPrincipal();

        KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
        AccessToken accessToken = session.getToken();
        KeycloakAccessTokenDTO keycloakAccessTokenDTO = KeycloakAccessTokenDTO.builder()
                .userName(accessToken.getPreferredUsername())
                .emailId(accessToken.getEmail())
                .lastName(accessToken.getFamilyName())
                .firstName(accessToken.getGivenName())
                .realmName(accessToken.getIssuer())
                .access(accessToken.getRealmAccess())
                .accessToken(session.getTokenString())
                .build();
        log.info(">> access token = {{}}", keycloakAccessTokenDTO);
        return "manager is here!!";
    }

    @PostMapping("/manager/path2")
    public String managerPost() {
        return "POST manager is here!";
    }

    @PostMapping("/manager/path3")
    public String receivePost(
            @RequestHeader HttpHeaders headers,
            @CookieValue(name = "httpclient-type", required = false, defaultValue = "undefined") String httpClientType
    ) {

        log.info(">> Cookie 'httpclient-type={}", httpClientType);

        log.info(">> headers {}", headers);

        return "success!!";
    }

    @GetMapping("/manager/default")
    public String afterLogin() {
        return "after login page";
    }
}

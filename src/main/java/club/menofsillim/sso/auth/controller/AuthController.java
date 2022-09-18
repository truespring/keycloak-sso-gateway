package club.menofsillim.sso.auth.controller;

import club.menofsillim.sso.auth.entity.KeycloakAccessTokenDTO;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RestController()
public class AuthController {

    /**
     * Keycloak Login
     */
    @GetMapping("/auth/login/{path}")
    public String loginRedirect(@PathVariable("path") String clientPath, HttpServletResponse response) {
        log.info(">> external request {{}}", clientPath);
        KeycloakPrincipal principal = (KeycloakPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

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
        response.setHeader("keycloak-access-token", keycloakAccessTokenDTO.getAccessToken());
        try {
            response.sendRedirect("http://localhost:8082/" + clientPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return "success!";
    }
    /**
     * Keycloak Login
     */
    @GetMapping("/auth/login")
    public String loginRedirect2() {
//        log.info(">> external request {{}}", clientPath);
        KeycloakPrincipal principal = (KeycloakPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

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
//        response.addHeader("keycloak-access-token", keycloakAccessTokenDTO.getAccessToken());
//        try {
//            response.sendRedirect(clientPath);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
        return "success!";
    }
}

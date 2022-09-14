package club.menofsillim.sso.auth.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.keycloak.representations.AccessToken;

@Getter
@ToString
public class KeycloakAccessTokenDTO {
    private final String userName;
    private final String emailId;
    private final String lastName;
    private final String firstName;
    private final String realmName;
    private final AccessToken.Access access;
    private final String accessToken;

    @Builder
    public KeycloakAccessTokenDTO(String userName, String emailId, String lastName, String firstName, String realmName, AccessToken.Access access, String accessToken) {
        this.userName = userName;
        this.emailId = emailId;
        this.lastName = lastName;
        this.firstName = firstName;
        this.realmName = realmName;
        this.access = access;
        this.accessToken = accessToken;
    }
}

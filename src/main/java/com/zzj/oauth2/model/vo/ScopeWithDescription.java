package com.zzj.oauth2.model.vo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

@Getter
@Setter
@ToString
public class ScopeWithDescription implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
    private static final Map<String, String> scopeDescriptions = Map.of(
            OidcScopes.PROFILE, "This application will be able to read your profile information.",
            "message.read", "This application will be able to read your message.",
            "message.write", "This application will be able to add new messages. It will also be able to edit and delete existing messages.",
            "other.scope", "This is another scope example of a scope description."
    );

    public final String scope;
    public final String description;

    public ScopeWithDescription(String scope) {
        this.scope = scope;
        this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
    }
}

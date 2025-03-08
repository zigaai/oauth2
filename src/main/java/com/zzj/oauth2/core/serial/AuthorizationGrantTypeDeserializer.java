package com.zzj.oauth2.core.serial;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.zzj.oauth2.core.util.JsonUtil;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.IOException;
import java.io.Serial;
import java.util.Map;

public class AuthorizationGrantTypeDeserializer extends StdDeserializer<AuthorizationGrantType> {
    @Serial
    private static final long serialVersionUID = 2884780317780523184L;

    public AuthorizationGrantTypeDeserializer() {
        super(AuthorizationGrantType.class);
    }

    @Override
    public AuthorizationGrantType deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        Map<String, String> map = JsonUtil.getInstance().readValue(p, new TypeReference<>() {});
        return new AuthorizationGrantType(map.values().stream().findFirst().orElse(null));
    }

}

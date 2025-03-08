package com.zzj.oauth2.security.model;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum UserType {
    ADMIN,
    USER;

    public static final Set<String> VALUES = Arrays.stream(values()).map(UserType::name).collect(Collectors.toSet());
}

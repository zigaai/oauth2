package com.zzj.oauth2.core.util;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.zzj.oauth2.core.constant.DateTimeConstant;
import com.zzj.oauth2.core.serial.*;
import lombok.experimental.UtilityClass;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.web.jackson2.WebJackson2Module;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Date;

@UtilityClass
public final class JsonUtil {

    public static String toJson(Object obj) throws JsonProcessingException {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER.writeValueAsString(obj);
    }

    public static <T> T readValue(String json, Class<T> clazz) throws JsonProcessingException {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER.readValue(json, clazz);
    }

    public static ObjectMapper getInstance() {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER;
    }

    public static ObjectMapper getRedisInstance() {
        return INNER.INSTANCE.REDIS_MAPPER;
    }

    @SuppressWarnings({"squid:S116", "squid:S125"})
    private enum INNER {
        INSTANCE;

        private final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper();
        private final ObjectMapper REDIS_MAPPER;

        INNER() {
            // datetime parse
            SimpleModule module = new SimpleModule();
            // 配置序列化
            module.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer());
            module.addSerializer(LocalDate.class, new LocalDateSerializer());
            module.addSerializer(LocalTime.class, new LocalTimeSerializer());
            module.addSerializer(Instant.class, new InstantSerializer());
            module.addSerializer(Date.class, new DateSerializer());
            // 配置反序列化
            module.addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer());
            module.addDeserializer(LocalDate.class, new LocalDateDeserializer());
            module.addDeserializer(LocalTime.class, new LocalTimeDeserializer());
            module.addDeserializer(Instant.class, new InstantDeserializer());
            module.addDeserializer(Date.class, new DateDeserializer());
            module.addDeserializer(AuthorizationGrantType.class, new AuthorizationGrantTypeDeserializer());


            DEFAULT_OBJECT_MAPPER.registerModule(new JavaTimeModule());
            DEFAULT_OBJECT_MAPPER.registerModule(module);
            DEFAULT_OBJECT_MAPPER.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true);
            DEFAULT_OBJECT_MAPPER.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            // 设置时区
            DEFAULT_OBJECT_MAPPER.setTimeZone(DateTimeConstant.UTC_ZONE);

            REDIS_MAPPER = DEFAULT_OBJECT_MAPPER.copy();
            REDIS_MAPPER.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
            REDIS_MAPPER.activateDefaultTyping(REDIS_MAPPER.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
            REDIS_MAPPER.registerModule(new CoreJackson2Module());
            REDIS_MAPPER.registerModule(new WebJackson2Module());
        }

    }
}

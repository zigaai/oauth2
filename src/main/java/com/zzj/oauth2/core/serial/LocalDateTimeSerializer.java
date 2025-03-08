package com.zzj.oauth2.core.serial;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.zzj.oauth2.core.constant.DateTimeConstant;

import java.io.IOException;
import java.time.LocalDateTime;

public class LocalDateTimeSerializer extends BaseDateSerializer<LocalDateTime> {

    @Override
    public void serialize(LocalDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (value != null) {
            long millis = value.atZone(DateTimeConstant.UTC_ZONE_ID).toInstant().toEpochMilli();
            gen.writeNumber(millis);
        }
    }

}
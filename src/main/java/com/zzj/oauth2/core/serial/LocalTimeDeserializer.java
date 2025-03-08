package com.zzj.oauth2.core.serial;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.LocalTime;

public class LocalTimeDeserializer extends JsonDeserializer<LocalTime> {
    @Override
    public LocalTime deserialize(JsonParser p, DeserializationContext deserializationContext) throws IOException {
        long secondOfDay = p.getValueAsLong();
        if (secondOfDay > 0) {
            return LocalTime.ofSecondOfDay(secondOfDay);
        }
        return null;
    }
}

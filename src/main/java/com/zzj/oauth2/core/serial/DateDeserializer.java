package com.zzj.oauth2.core.serial;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.Date;

public class DateDeserializer extends JsonDeserializer<Date> {

    @Override
    public Date deserialize(JsonParser p, DeserializationContext deserializationContext) throws IOException {
        long timestamp = p.getValueAsLong();
        if (timestamp > 0) {
            return new Date(timestamp);
        } else {
            return null;
        }
    }

}

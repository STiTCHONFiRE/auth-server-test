package ru.stitchonfire.authserver.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Converter
public class ListToStringConverter implements AttributeConverter<List<String>, String> {
    @Override
    public String convertToDatabaseColumn(List<String> strings) {
        return strings == null ? null : String.join(",", strings);
    }

    @Override
    public List<String> convertToEntityAttribute(String s) {
        return s == null ? Collections.emptyList() : Arrays.asList(s.split(","));
    }
}

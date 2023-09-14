package com.example.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.codec.json.Jackson2JsonEncoder;

public record JSONResponse<T>(int code, T data, String message) {
    public static <T> JSONResponse<T> success(T data) {
        return new JSONResponse<>(200, data, "请求成功");
    }

    public static <T> JSONResponse<T> success() {
        return success(null);
    }

    public String toJSONString() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this);
    }
}

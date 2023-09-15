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

    public static <T> JSONResponse<T> fail(int code, String message) {
        return new JSONResponse<>(code, null, message);
    }

    public static <T> JSONResponse<T> fail(int code) {
        return fail(code, "出错了");
    }

    public static <T> JSONResponse<T> fail(String message) {
        return fail(0, message);
    }

    public static <T> JSONResponse<T> fail() {
        return fail(0, "出错了");
    }
}

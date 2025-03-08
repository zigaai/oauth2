package com.zzj.oauth2.core.module;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;

@Getter
@Setter
@ToString
@JsonInclude
public class Res<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private int code;

    /**
     * 响应信息
     */
    private String msg;

    /**
     * 响应结果
     */
    @SuppressWarnings("squid:S1948")
    private T data;

    public static Res<Void> success() {
        return success(ResponseState.SUCCESS.getMsg());
    }

    public static <T> Res<T> success(T data) {
        return success(ResponseState.SUCCESS.getMsg(), data);
    }

    public static <T> Res<T> success(String message) {
        return success(message, null);
    }

    public static <T> Res<T> success(String message, T data) {
        return build(ResponseState.SUCCESS.getValue(), message, data);
    }

    public static <T> Res<T> fail(T data) {
        return fail(ResponseState.FAILED.getMsg(), data);
    }

    public static <T> Res<T> fail(String message) {
        return fail(message, null);
    }

    public static <T> Res<T> fail(String message, T data) {
        return build(ResponseState.FAILED.getValue(), message, data);
    }

    public static <T> Res<T> forbidden(String msg) {
        return forbidden(msg, null);
    }

    public static <T> Res<T> forbidden(T data) {
        return forbidden(ResponseState.FORBIDDEN.getMsg(), data);
    }

    public static <T> Res<T> forbidden(String message, T data) {
        return build(ResponseState.FORBIDDEN.getValue(), message, data);
    }

    public static <T> Res<T> unauthorized(String msg) {
        return unauthorized(msg, null);
    }

    public static <T> Res<T> unauthorized(T data) {
        return unauthorized(ResponseState.UNAUTHORIZED.getMsg(), data);
    }

    public static <T> Res<T> needLogin(String msg) {
        return build(ResponseState.NEED_LOGIN.getValue(), msg, null);
    }

    public static <T> Res<T> unauthorized(String message, T data) {
        return build(ResponseState.UNAUTHORIZED.getValue(), message, data);
    }

    public static <T> Res<T> badRequest(String message) {
        return badRequest(message, null);
    }

    public static <T> Res<T> badRequest(String message, T data) {
        return build(ResponseState.BAD_REQUEST.getValue(), message, data);
    }

    public static <T> Res<T> unknownError(String message) {
        return build(ResponseState.UNKNOWN_ERROR.getValue(), message, null);
    }

    public static <T> Res<T> methodNotAllowed(String message) {
        return build(ResponseState.METHOD_NOT_ALLOW.getValue(), message, null);
    }

    public static <T> Res<T> notFound() {
        return build(ResponseState.NOT_FOUND.getValue(), ResponseState.NOT_FOUND.getMsg(), null);
    }

    public static <T> Res<T> notFound(String message) {
        return build(ResponseState.NOT_FOUND.getValue(), message, null);
    }

    public static <T> Res<T> build(Integer code, String message, T data) {
        Res<T> res = new Res<>();
        res.code = code;
        res.msg = message;
        res.data = data;
        return res;
    }

    public static <T> T unwrap(Res<T> res) {
        if (res == null) {
            return null;
        }
        return res.getData();
    }

}
package com.zzj.oauth2.core.module;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ResponseState {
    SUCCESS(20000, "成功"),
    FAILED(30001, "失败"),
    BAD_REQUEST(40000, "参数错误"),
    UNAUTHORIZED(40001, "用户未登录"),
    NEED_LOGIN(40011, "请重新登录"),
    FORBIDDEN(40003, "无权访问"),
    NOT_FOUND(40004, "页面不存在"),
    METHOD_NOT_ALLOW(40005, "不支持的方法请求"),
    UNKNOWN_ERROR(50000, "未知错误");

    private final int value;
    private final String msg;
}

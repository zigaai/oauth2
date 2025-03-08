package com.zzj.oauth2.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.zzj.oauth2.security.exception.JwtExpiredException;
import com.zzj.oauth2.security.exception.JwtInvalidException;
import com.zzj.oauth2.security.model.PayloadDTO;
import com.zzj.oauth2.security.model.UPMSToken;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.tuple.Pair;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@UtilityClass
public final class JWTUtil {

    public static UPMSToken generateToken(PayloadDTO claims, KeyPair keyPairs) throws JsonProcessingException, JOSEException {
        long expiresIn = claims.getExpiresIn();
        // 创建JWS头，设置签名算法和类型
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).
                type(JOSEObjectType.JWT)
                .build();
        long iat = System.currentTimeMillis() / 1000;
        long exp = iat + expiresIn;
        claims.setIat(iat);
        claims.setExp(exp);
        // 将负载信息封装到Payload中
        Payload payload = new Payload(JsonUtil.toJson(claims));
        // 创建JWS对象
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        // 创建HMAC签名器
        JWSSigner jwsSigner = new RSASSASigner(keyPairs.getPrivate());
        // 签名
        jwsObject.sign(jwsSigner);
        String tokenVal = jwsObject.serialize();
        return new UPMSToken(tokenVal, iat, exp, expiresIn);
    }

    public static Pair<JWSObject, PayloadDTO> parseUnverified(String token) throws ParseException, JsonProcessingException {
        // 从token中解析JWS对象
        JWSObject jwsObject = JWSObject.parse(token);
        // 创建HMAC验证器
        String payloadStr = jwsObject.getPayload().toString();
        PayloadDTO payloadDTO = JsonUtil.readValue(payloadStr, PayloadDTO.class);
        if (payloadDTO.getUsername() == null) {
            payloadDTO.setUsername(payloadDTO.getSub());
        }
        return Pair.of(jwsObject, payloadDTO);
    }

    public static void check(JWSObject jwsObject, PayloadDTO payload, KeyPair keyPairs) throws JOSEException {
        JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) keyPairs.getPublic());
        if (!jwsObject.verify(jwsVerifier)) {
            throw new JwtInvalidException("token签名不合法, 请重新登录");
        }
        if (TimeUnit.SECONDS.toMillis(payload.getExp()) < new Date().getTime()) {
            throw new JwtExpiredException("token已过期, 请重新登录");
        }
    }

}
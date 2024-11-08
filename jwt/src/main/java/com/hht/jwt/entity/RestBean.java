package com.hht.jwt.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import io.netty.handler.codec.json.JsonObjectDecoder;
import org.slf4j.MDC;

import java.util.Optional;

/**
 * @author 何鸿涛
 * @date 2024/11/3 下午3:15
 */
public record RestBean <T> (long id,int code,T data ,String message){
    public static<T> RestBean<T> success(T data){
        return new RestBean<>(requestId(),200,data,"请求成功");
    }

    public static<T> RestBean<T> success(){
        return success(null);
    }

    public static<T> RestBean<T> failure(int code,String message){
        return new RestBean<>(requestId(),code,null,message);
    }

    public static<T> RestBean<T> forbidden(String message){
        return failure(403,message);
    }

    public static<T> RestBean<T> unauthorized(String message){
        return failure(401,message);
    }

    //快速将当前实体转化为JSON字符串格式
    public String asJsonString(){
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }

    /**
     *
     * @return ID
     */
    private static long requestId(){
        String requestId = Optional.ofNullable(MDC.get("reqId")).orElse("0");
        return Long.parseLong(requestId);
    }
}

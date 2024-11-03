package com.hht.jwt.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author 何鸿涛
 * @date 2024/11/3 下午4:15
 */
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    private String key;

    @Value("${spring.security.jwt.expire-time}")
    private int expire_time;

    @Resource
    StringRedisTemplate template;


    public String createJwt(UserDetails user,String username,int userId){
        Algorithm algorithm = Algorithm.HMAC256(key);
        Date expire_time = this.expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id",userId)
                .withClaim("name",username)
                .withClaim("authorities",user.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expire_time)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public Date expireTime(){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR,expire_time);
        return calendar.getTime();
    }


    /**
     *
     * @param headerToken
     * @return com.auth0.jwt.interfaces.DecodedJWT
     * @author xinggang
     * @create 2024/11/3
     **/


    public DecodedJWT resolveJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if(token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        //构建jwt解码器
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT verify = jwtVerifier.verify(token);
        Map<String, Claim> claims = verify.getClaims();
        Date expirationDate = claims.get("exp").asDate();
        boolean isExpired = new Date().after(expirationDate);
        if (isExpired) {
            return null;
        } else {
            return verify;
        }

    }

    /**
     * 
     *
     * @param headerToken
     * @return java.lang.String
     * @author 何鸿涛
     * @create 2024/11/3
     **/

    public String convertToken(String headerToken){
        if(headerToken != null || !headerToken.startsWith("Bearer")) return null;
        return headerToken.substring(7);
    }

    public UserDetails toUser(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        return User
                .withUsername(claims.get("name").asString())
                .password("******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public Integer toId(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    /**
     *
     * @param headerToken
     * @return
     * @author xinggang
     * @create 2024/11/3
     **/


    public boolean invalidJwt(String headerToken){
        String token = this.convertToken(headerToken);
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT verify = jwtVerifier.verify(token);

    }

    private boolean deleteToken(String uuid,Date time){
        if(this.isBlacklistedInRedis(uuid)){
            return false;
        }

        Date now = new Date();
        long max = Math.max(time.getTime() - now.getTime(), 0);
        template.opsForValue().set("jwt:blacklist:"+uuid,"",expire_time, TimeUnit.MICROSECONDS);
        return true;
    }

    private Boolean  isBlacklistedInRedis(String uuid){
        return Boolean.TRUE.equals(template.hasKey("jwt:blacklist:" + uuid));
    }
}

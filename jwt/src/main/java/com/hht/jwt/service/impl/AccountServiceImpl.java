package com.hht.jwt.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hht.jwt.entity.dto.Account;
import com.hht.jwt.mapper.AccountMapper;
import com.hht.jwt.service.AccountService;
import jakarta.annotation.Resource;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serializable;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    @Resource
    AmqpTemplate rabbitTemplate;

    @Resource
    StringRedisTemplate stringRedisTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByNameOrEmail(username);
        if (account == null) throw new UsernameNotFoundException("用户名或密码错误");
        return User
                .withUsername(username)
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Override
    public Account findAccountByNameOrEmail(String text) {
        return this.query()
                .eq("username",text).or()
                .eq("email",text)
                .one();
    }

    @Override
    public String registerEmailVerifyCode(String type, String email, String address) {
        Random random = new Random();
        int code = random.nextInt(899999) + 100000;
        Map<String,Object> data = Map.of("type", type, "email", email, "code", code);
        rabbitTemplate.convertAndSend("mail",data);
        stringRedisTemplate.opsForValue().set("verify:email:data:"+email,String.valueOf(code),3, TimeUnit.MINUTES);
        return null;
    }
}

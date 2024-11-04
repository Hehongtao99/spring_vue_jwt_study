package com.hht.jwt.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.hht.jwt.entity.dto.Account;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account> , UserDetailsService {
    Account findAccountByNameOrEmail(String text);

    String registerEmailVerifyCode(String type, String email, String address);
}

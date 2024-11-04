package com.hht.jwt.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.hht.jwt.entity.dto.Account;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper extends BaseMapper<Account> {
}

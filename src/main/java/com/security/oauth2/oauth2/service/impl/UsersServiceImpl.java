package com.security.oauth2.oauth2.service.impl;

import com.security.oauth2.oauth2.entity.Users;
import com.security.oauth2.oauth2.mapper.UsersMapper;
import com.security.oauth2.oauth2.service.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author Hu
 * @date 2019/3/19 14:53
 */

@Service
public class UsersServiceImpl implements UsersService {

    @Autowired
    private UsersMapper usersMapper;

    @Override
    public Users findUserByUsername(String username) {
        return usersMapper.findUserByUsername(username);
    }
}

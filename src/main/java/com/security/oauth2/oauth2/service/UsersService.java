package com.security.oauth2.oauth2.service;

import com.security.oauth2.oauth2.entity.Users;

/**
 * @author Hu
 * @date 2019/3/19 14:53
 */

public interface UsersService {

    Users findUserByUsername(String username);
}

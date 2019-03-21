package com.security.oauth2.oauth2.mapper;

import com.security.oauth2.oauth2.entity.Users;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author Hu
 * @date 2019/3/19 14:48
 */

@Mapper
public interface UsersMapper {

    Users findUserByUsername(String username);

}

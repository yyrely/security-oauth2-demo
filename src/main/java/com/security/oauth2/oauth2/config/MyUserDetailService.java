package com.security.oauth2.oauth2.config;

import com.security.oauth2.oauth2.entity.Users;
import com.security.oauth2.oauth2.mapper.UsersMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author Hu
 * @date 2019/3/21 15:36
 */

@Service
public class MyUserDetailService implements UserDetailsService {


    @Autowired
    private UsersMapper usersMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = usersMapper.findUserByUsername(username);
        return new SUser(user);
    }
}

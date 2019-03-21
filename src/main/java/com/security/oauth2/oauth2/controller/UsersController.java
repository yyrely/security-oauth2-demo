package com.security.oauth2.oauth2.controller;

import com.security.oauth2.oauth2.entity.Users;
import com.security.oauth2.oauth2.service.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Hu
 * @date 2019/3/19 14:38
 */

@RestController
@RequestMapping("users")
public class UsersController {

    @Autowired
    private UsersService usersService;

    @GetMapping("/test")
    public void test() {
        System.out.println("hello world");
    }

    @GetMapping("/{username}")
    private Map<String,String> findUserByUsername(@PathVariable("username") String username) {
        Users users = usersService.findUserByUsername(username);
        Map<String,String> map = new HashMap<>();
        map.put("username" , users.getUsername());
        return map;
    }

}

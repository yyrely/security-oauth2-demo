package com.security.oauth2.oauth2.entity;

import lombok.Data;

/**
 * @author Hu
 * @date 2019/3/19 14:51
 */

@Data
public class Users {

    private Long id;

    private String username;

    private String password;

    private String role;

}

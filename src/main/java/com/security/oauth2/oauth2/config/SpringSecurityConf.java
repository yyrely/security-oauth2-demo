package com.security.oauth2.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Hu
 * @date 2019/3/14 10:34
 */

@Configuration
@EnableWebSecurity
public class SpringSecurityConf extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailService userDetailsService;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //关闭session，不再使用
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable()
                //权限设置管理
                .authorizeRequests()
                //放行以下url
                .antMatchers("/oauth/token").permitAll()
                //给对应的url设置权限（只有ADMIN才可以访问，除去ROLE_前缀，spring帮我们处理了）
                //在数据库中用户的role字段是要加ROLE_的ROLE_ADMIN才可以匹配到这里的ADMIN
                .antMatchers("/users/lala/*").authenticated()
                //所有请求都需要授权（除了放行的）
                .anyRequest().authenticated()
                .and()
                //开启登录
                .formLogin();

        //在LogoutFilter之前增加鉴权过滤器
        //http.addFilterBefore(authorizationFilter, LogoutFilter.class);
        //用自定义的授权过滤器覆盖UsernamePasswordAuthenticationFilter
        http.addFilterAt(createTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    private TokenAuthenticationFilter createTokenAuthenticationFilter() throws Exception {
        return new TokenAuthenticationFilter(authenticationManagerBean(), redisTemplate, objectMapper,clientDetailsService,authorizationServerTokenServices);
    }


    //密码加密器，在授权时，框架为我们解析用户名密码时，密码会通过加密器加密在进行比较
    //将密码加密器交给spring管理，在注册时，密码也是需要加密的，再存入数据库中
    //用户输入登录的密码用加密器加密，再与数据库中查询到的用户密码比较
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth
                //设置使用自己实现的userDetailsService（loadUserByUsername）
                .userDetailsService(userDetailsService)
                //设置密码加密方式
                .passwordEncoder(bCryptPasswordEncoder());
    }
}

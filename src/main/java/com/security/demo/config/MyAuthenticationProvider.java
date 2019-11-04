//package com.security.demo.config;
//
//import com.security.demo.service.MyUserDetailsService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.Collection;
//@Component
//public class MyAuthenticationProvider implements AuthenticationProvider {
//    @Autowired
//    private MyUserDetailsService userService;
//    @Autowired
//    PasswordEncoder passwordEncoder;
//    @Override
//    public Authentication authenticate(Authentication auth) throws AuthenticationException {
//        String username = auth.getName();
//        String password = (String) auth.getCredentials();
//        UserDetails user = userService.loadUserByUsername(username);
//        if(user==null){
//            throw new BadCredentialsException("用户名不存在");
//        }
//        boolean matches = passwordEncoder.matches(password, user.getPassword());
//        if(!matches){
//            throw new BadCredentialsException("密码不正确");
//        }
//        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
//        return new UsernamePasswordAuthenticationToken(user, password, authorities);
//    }
//    @Override
//    public boolean supports(Class<?> aClass) {
//        return true;
//    }
//}

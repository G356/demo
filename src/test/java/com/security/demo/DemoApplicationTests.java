package com.security.demo;
import com.security.demo.entity.User;
import com.security.demo.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import javax.annotation.Resource;

@SpringBootTest
class DemoApplicationTests {
    @Resource
    UserMapper userMapper;
    @Test
    void contextLoads() {
    }
    @Test
    void update() {
        User user = new User();
        user.setUsername("user");
        String password="123456";
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String hashPass=passwordEncoder.encode(password);
        System.out.println("密码一致"+passwordEncoder.matches(password, hashPass));
        user.setPassword(hashPass);
        userMapper.update(user);
    }

}

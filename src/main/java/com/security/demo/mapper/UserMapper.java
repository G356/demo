package com.security.demo.mapper;
import com.security.demo.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
@Mapper
public interface UserMapper {
    @Select( "select id , username , password from user where username = #{username}" )
    User loadUserByUsername(@Param("username") String username);
    @Update("update user set password = #{password} where username=#{username}")
    int update(User user);
}

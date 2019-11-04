package com.security.demo.config;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.*;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //@Autowired MyAuthenticationProvider myAuthenticationProvider;

    //@Autowired
    //public void configureGlobal(AuthenticationManagerBuilder auth) {
    //   auth.authenticationProvider(myAuthenticationProvider);
    //}
    //@Override
    //protected void configure(HttpSecurity http) throws Exception {
    //    http.authorizeRequests()
    //            .antMatchers("/","/index","/login","/login-error","/401","/css/**","/js/**").permitAll()
    //            .anyRequest().authenticated()
    //            .and()
    //            .formLogin().loginPage( "/login" ).failureUrl( "/login-error" )
    //            .and()
    //            .exceptionHandling().accessDeniedPage( "/401" );
    //    http.logout().logoutSuccessUrl( "/" );
    //    //http.csrf().sessionAuthenticationStrategy(sessionAuthenticationStrategy());
    //    http.csrf().csrfTokenRepository(csrfTokenRepository());
    //}
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .addFilterAfter(customAuthFilter(), RequestHeaderAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/","/index","/login","/login-error","/401","/css/**","/js/**", "/csrf").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().csrfTokenRepository(csrfTokenRepository())
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                .and()
                .formLogin().disable();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("password").roles("USER")
                .and()
                .withUser("admin").password("admin").roles("ADMIN");
    }
    @Bean
    public UsernamePasswordAuthenticationFilter customAuthFilter() throws Exception {
        UsernamePasswordAuthenticationFilter authenFilter = new CustomAuthenticationFilter();
        authenFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
        authenFilter.setUsernameParameter("username");
        authenFilter.setPasswordParameter("password");
        authenFilter.setAuthenticationManager(authenticationManagerBean());
        authenFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        authenFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
        return authenFilter;
    }
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new SimpleUrlAuthenticationSuccessHandler("/");
    }
    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new CompositeSessionAuthenticationStrategy(Arrays.asList(
                new ChangeSessionIdAuthenticationStrategy(),
                new CsrfAuthenticationStrategy(csrfTokenRepository())
        ));
    }
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new LazyCsrfTokenRepository(new HttpSessionCsrfTokenRepository());
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
}

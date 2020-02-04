package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Auther: r.cheng
 * @Date: 2020/2/4 11:35
 * @Description: Spring Security 配置类
 */
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserService userService;

    /**
     * 登录、登出、授权相关配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录相关配置
        http.formLogin()
                .loginPage("/loginPage") // 设置登录页面（登录url）
                .loginProcessingUrl("/login") // 登录表单action请求路径
//                .successForwardUrl("/index") // 登录成功转发路径
                .successHandler(new AuthenticationSuccessHandler() { // 登录成功处理器
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 重定向到首页
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                })
//                .failureForwardUrl("/login") // 登陆失败转发路径
                .failureHandler(new AuthenticationFailureHandler() { // 登录失败处理器
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        // 保存错误信息转发到登陆页面
                        request.setAttribute("error", e.getMessage());
                        request.getRequestDispatcher("/loginPage").forward(request, response);
                    }
                });
        // 登出相关配置
        http.logout()
            .logoutUrl("/logout") // 设置退出登录url
//            .logoutSuccessUrl("/index") // 设置退出登录成功url
            .logoutSuccessHandler(new LogoutSuccessHandler() { // 登出成功处理器
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect(request.getContextPath() + "/index");
                }
            });

        // 授权相关配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("ADMIN", "USER") // 设置/letter请求ADMIN、ADMIN都可以访问
                .antMatchers("/admin").hasAnyAuthority("/admin", "ADMIN") // /admin请求只能ADMIN访问
                .and()
                .exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() { // 设置出现异常的拒绝处理器
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                response.sendRedirect(request.getContextPath() + "/denied");
            }
        });

        // 增加自定义过滤器，实现验证码过滤
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                // 将ServletRequest、ServletResponse转为实现类
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                // 如果是登录url
                if ("/login".equals(request.getServletPath())) {
                    // 获取验证码
                    String verifyCode = request.getParameter("verifyCode");
                    // 模拟固定值，项目中需要从session或者Redis中获取验证码
                    if (verifyCode == null || !"1234".equals(verifyCode)) {
                        request.setAttribute("error", "验证码错误!");
                        request.getRequestDispatcher("/loginPage").forward(request, response);
                        return;
                    }
                }
                // 不是登录或者验证码正确，则放行下一个过滤器
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class); // 在登录之前验证验证码是否正确(UsernamePasswordAuthenticationFilter账号密码过滤器)

        // 记住我配置
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl()) // 将token新报保存在内存中,将随机串保存在cookie中
                .tokenValiditySeconds(3600 * 24) // token保存时间
                .userDetailsService(userService); // 在执行登陆的时候先排查是否remember-me
    }

    /**
     * 处理认证功能
     * AuthenticationManager：认证功能核心接口
     * AuthenticationManagerBuilder：创建获取 AuthenticationManager
     * AuthenticationProvider: AuthenticationManager的默认实现类
     * ProviderManager: 管理 AuthenticationProvider，持有多个AuthenticationProvider，每个AuthenticationProvider管理一种认证(账号密码、QQ、微信...)
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 自定义认证规则
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication: 认证信息封装
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                // 获取用户名
                String username = authentication.getName();
                //获取密码
                String password = (String) authentication.getCredentials();
                // 查询用户
                User user = userService.findUserByName(username);
                if (user == null) {
                    throw new UsernameNotFoundException("用户不存在!");
                }
                // 密码加密
                password = CommunityUtil.md5(password + user.getSalt());
                if (!password.equals(user.getPassword())) {
                    throw new BadCredentialsException("密码不正确!");
                }
                // 认证成功，保存用户信息
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            /**
             *  当前AuthenticationProvider支持哪种认证形式
             *  UsernamePasswordAuthenticationToken: Authentication常用实现类，使用用户名密码认证
             */
            @Override
            public boolean supports(Class<?> clazz) {
                return UsernamePasswordAuthenticationToken.class.equals(clazz);
            }
        });
    }

    /**
     * 配置处理静态资源，一般来说静态资源是不会拦截的
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源访问
        web.ignoring().antMatchers("/resources/**");
    }
}

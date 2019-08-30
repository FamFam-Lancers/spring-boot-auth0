package com.example.springbootauth0.config;

import com.example.springbootauth0.service.CustomOidcUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private CustomOidcUserService oidcUserService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and().logout().logoutSuccessUrl("/login").invalidateHttpSession(true).deleteCookies("JSESSIONID").permitAll()
                .and().oauth2Login().loginPage("/login").permitAll()
                .userInfoEndpoint().oidcUserService(oidcUserService);

                // 直接Auth0へ転送する場合は下記を使う
//                .and().oauth2Login().loginPage("/oauth2/authorization/auth0").permitAll()
    }

    /**
     * OAuth2.0を用いてログインした場合のユーザーの権限を設定
     */
    private GrantedAuthoritiesMapper oauth2UserAuthoritiesMapper() {
        // インタフェース的には複数件受け取ることができるが、実際には権限情報(ROLE_USER)の１件のみが渡される
        return authorities -> {
            List<GrantedAuthority> mappedAuthorities = new ArrayList<>();
            for (GrantedAuthority authority : authorities) {
                // オリジナルの権限情報は引き継ぐ
                mappedAuthorities.add(authority);
                if (OAuth2UserAuthority.class.isInstance(authority)) {
                    // OAuth 2.0 Login機能でログインしたユーザに与える権限情報(ROLE_OAUTH_USER)を追加
                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_OAUTH_USER"));
                }
            }
            return mappedAuthorities;
        };
    }


}

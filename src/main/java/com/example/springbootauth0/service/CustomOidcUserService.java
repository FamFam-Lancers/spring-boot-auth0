package com.example.springbootauth0.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomOidcUserService extends OidcUserService {

    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        var user = super.loadUser(userRequest);

        var mappedAuthorities = new ArrayList<GrantedAuthority>();

        mappedAuthorities.addAll(user.getAuthorities());

        // 実際にはここでDB等からロールをセットする
        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_AAA"));


        return new DefaultOidcUser(mappedAuthorities, user.getIdToken(), user.getUserInfo());
    }
}

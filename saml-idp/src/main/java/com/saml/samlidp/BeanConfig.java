package com.saml.samlidp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;
 
@Configuration
public class BeanConfig extends SamlIdentityProviderServerBeanConfiguration {
    private final AppConfig config;
 
    public BeanConfig(AppConfig config) {
        this.config = config;
    }
 
    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return config;
    }
 
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = 
            User.withDefaultPasswordEncoder()
            .username("user") // This can be an email too
            .password("password")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
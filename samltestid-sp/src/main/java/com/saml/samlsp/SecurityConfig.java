package com.saml.samlsp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("classpath:credentials/private.key")
    RSAPrivateKey privateKey;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
            new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository());
        Saml2MetadataFilter filter = new Saml2MetadataFilter(
            relyingPartyRegistrationResolver,
            new OpenSamlMetadataResolver());
        http
            .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
            .authorizeHttpRequests((authorize) -> authorize
                .antMatchers("/logout", "/logout/saml2/slo", "/welcome").permitAll()
                .anyRequest()
                .authenticated()

            )
            .saml2Login(Customizer.withDefaults())
            .saml2Logout(Customizer.withDefaults())
            .logout(logout -> logout.clearAuthentication(true)
                .deleteCookies("JSESSIONID", "shib_idp_session", "shib_idp_persistent_ss")
                .invalidateHttpSession(true)
                )
            ;
        // @formatter:on

    }

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
            .fromMetadataLocation("https://samltest.id/saml/idp")
            .registrationId("samlexample")
            .decryptionX509Credentials(
                (c) -> c.add(Saml2X509Credential.decryption(this.privateKey, relyingPartyCertificate())))
            .signingX509Credentials(
                (c) -> c.add(Saml2X509Credential.signing(this.privateKey, relyingPartyCertificate())))
            .singleLogoutServiceLocation("{baseUrl}/logout")
            .singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT)
            .build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

    X509Certificate relyingPartyCertificate() {
        Resource resource = new ClassPathResource("credentials/public.crt");
        try (InputStream is = resource.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
        catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

}
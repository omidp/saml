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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

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
            .logout(logout -> logout.clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .logoutRequestMatcher(new AntPathRequestMatcher("/saml2/logout/myidp.com", "POST"))

            )
            ;
        // @formatter:on

    }

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
            .fromMetadataLocation("http://localhost:8081/saml/idp/metadata")
            .registrationId("myidp.com")
//            .idpWebSsoUrl("http://localhost:8081/saml/idp/select")
            .assertingPartyDetails(ap -> {
                ap.singleSignOnServiceLocation("http://localhost:8081/saml/idp/select")
                    .entityId("myidp.com")
                    .wantAuthnRequestsSigned(false)
                    ;
            })
            .signingX509Credentials(
                (c) -> c.add(Saml2X509Credential.signing(this.privateKey, relyingPartyCertificate())))
//            .singleLogoutServiceLocation("{baseUrl}/saml2/logout/myidp.com")
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
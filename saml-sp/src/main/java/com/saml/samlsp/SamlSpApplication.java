package com.saml.samlsp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.util.stream.Stream;

@SpringBootApplication(exclude = Saml2RelyingPartyAutoConfiguration.class)
public class SamlSpApplication {

	public static void main(String[] args) {
		SpringApplication.run(SamlSpApplication.class, args);
	}


	@Bean
	CommandLineRunner cmdLineRunner(ApplicationContext ctx){
		return args -> {
			String[] beanDefinitionNames = ctx.getBeanDefinitionNames();
			for (String beanDefinitionName : beanDefinitionNames) {
				if(beanDefinitionName.contains("saml")){
					System.out.println(beanDefinitionName);
				}
			}

		};
	}

}

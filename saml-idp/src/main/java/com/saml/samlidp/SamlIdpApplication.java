package com.saml.samlidp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SamlIdpApplication {

	public static void main(String[] args) {
		SpringApplication.run(SamlIdpApplication.class, args);
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

package net.samitkumar.spring_oauth2_authorization_server;

import org.springframework.boot.SpringApplication;

public class TestSpringOauth2AuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.from(SpringOauth2AuthorizationServerApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}

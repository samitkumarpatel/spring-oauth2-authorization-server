package net.samitkumar.spring_oauth2_authorization_server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class SpringOauth2AuthorizationServerApplicationTests {

	@Test
	void contextLoads() {
	}

}

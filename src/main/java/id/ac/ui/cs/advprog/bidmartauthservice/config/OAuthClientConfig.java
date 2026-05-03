package id.ac.ui.cs.advprog.bidmartauthservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

@Configuration
public class OAuthClientConfig {
    @Bean
    public RestOperations restOperations() {
        return new RestTemplate();
    }
}

package id.ac.ui.cs.advprog.bidmartauthservice.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.simp.config.SimpleBrokerRegistration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.StompWebSocketEndpointRegistration;
import org.springframework.web.socket.config.annotation.SockJsServiceRegistration;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("unit")
class ConfigCoverageTest {

    @Test
    void securityConfigShouldProvidePasswordEncoder() {
        PasswordEncoder passwordEncoder = new SecurityConfig().passwordEncoder();

        assertTrue(passwordEncoder.matches("secret", passwordEncoder.encode("secret")));
    }

    @Test
    void webSocketConfigShouldRegisterBrokerAndEndpoint() {
        WebSocketConfig webSocketConfig = new WebSocketConfig();
        StompEndpointRegistry stompEndpointRegistry = mock(StompEndpointRegistry.class);
        StompWebSocketEndpointRegistration endpointRegistration = mock(StompWebSocketEndpointRegistration.class);
        SockJsServiceRegistration sockJsServiceRegistration = mock(SockJsServiceRegistration.class);
        MessageBrokerRegistry messageBrokerRegistry = mock(MessageBrokerRegistry.class);
        SimpleBrokerRegistration simpleBrokerRegistration = mock(SimpleBrokerRegistration.class);

        when(stompEndpointRegistry.addEndpoint("/ws")).thenReturn(endpointRegistration);
        when(endpointRegistration.setAllowedOriginPatterns("*")).thenReturn(endpointRegistration);
        when(endpointRegistration.withSockJS()).thenReturn(sockJsServiceRegistration);
        when(messageBrokerRegistry.enableSimpleBroker("/topic", "/queue")).thenReturn(simpleBrokerRegistration);
        when(simpleBrokerRegistration.setTaskScheduler(any())).thenReturn(simpleBrokerRegistration);
        when(simpleBrokerRegistration.setHeartbeatValue(any(long[].class))).thenReturn(simpleBrokerRegistration);

        webSocketConfig.registerStompEndpoints(stompEndpointRegistry);
        webSocketConfig.configureMessageBroker(messageBrokerRegistry);

        verify(stompEndpointRegistry).addEndpoint("/ws");
        verify(endpointRegistration).setAllowedOriginPatterns("*");
        verify(endpointRegistration).withSockJS();
        verify(messageBrokerRegistry).enableSimpleBroker("/topic", "/queue");
        verify(simpleBrokerRegistration).setHeartbeatValue(any(long[].class));
        verify(messageBrokerRegistry).setApplicationDestinationPrefixes("/app");
    }
}
package id.ac.ui.cs.advprog.bidmartauthservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * WebSocket configuration for real-time session revocation notifications.
 * Enables STOMP (Simple Text Oriented Messaging Protocol) over WebSocket.
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Bean
    public ThreadPoolTaskScheduler websocketTaskScheduler() {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setPoolSize(1);
        taskScheduler.setThreadNamePrefix("websocket-broker-");
        taskScheduler.initialize();
        return taskScheduler;
    }

    /**
     * Configure STOMP endpoints and enable SockJS fallback for older browsers.
     */
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry
                .addEndpoint("/ws")
                .setAllowedOriginPatterns("*")
                .withSockJS();
    }

    /**
     * Configure message broker for topic-based messaging.
     * - ApplicationDestinationPrefix: prefix for messages sent to @MessageMapping
     * - SimpleBroker: in-memory broker for /topic and /queue destinations
     * - Relay: can be configured for external AMQP/RabbitMQ broker for production
     */
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config
                .enableSimpleBroker("/topic", "/queue")
                .setTaskScheduler(websocketTaskScheduler())
                .setHeartbeatValue(new long[]{25000, 25000});
        
        config.setApplicationDestinationPrefixes("/app");
    }
}

package id.ac.ui.cs.advprog.bidmartauthservice.config;

import id.ac.ui.cs.advprog.bidmartauthservice.repository.RefreshTokenRepository;
import id.ac.ui.cs.advprog.bidmartauthservice.service.RedisSessionCacheService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * JWT Authentication Filter that validates tokens with both Redis cache and database fallback.
 * 
 * Flow:
 * 1. Extract tokenId from JWT claims
 * 2. Check Redis cache first (O(1) lookup) - if found, session is valid
 * 3. If not in Redis, fall back to checking the database for persistence
 * 4. If session is invalid, reject the request with 401 Unauthorized
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = Logger.getLogger(JwtAuthenticationFilter.class.getName());

    @Value("${app.auth.jwt.secret}")
    private String jwtSecret;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RedisSessionCacheService redisSessionCacheService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                Claims claims = Jwts.parser()
                        .verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();

                if ("access".equals(claims.get("type"))) {                    
                    String tokenIdStr = claims.get("tokenId", String.class);
                    
                    if (tokenIdStr == null) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token structure.");
                        return;
                    }

                    UUID tokenId = UUID.fromString(tokenIdStr);
                    
                    // Check Redis cache first (fast path)
                    if (redisSessionCacheService.isSessionActive(tokenId)) {
                        // Session is active, request is valid
                        request.setAttribute("userId", claims.getSubject());
                        request.setAttribute("userEmail", claims.get("email", String.class));
                    } else {
                        // Redis miss - fall back to database check
                        boolean isSessionActive = refreshTokenRepository.findByTokenIdAndRevokedFalse(tokenId).isPresent();

                        if (!isSessionActive) {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session has been revoked.");
                            return;
                        }

                        // Session is active, set attributes
                        request.setAttribute("userId", claims.getSubject());
                        request.setAttribute("userEmail", claims.get("email", String.class));
                    }
                }
            } catch (Exception ignored) {
                // Invalid token (expired / signature wrong), do not set attributes
                logger.warning("Failed to parse/validate JWT token");
            }
        }

        filterChain.doFilter(request, response);
    }
}
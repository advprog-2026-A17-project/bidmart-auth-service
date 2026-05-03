package id.ac.ui.cs.advprog.bidmartauthservice.config;

import id.ac.ui.cs.advprog.bidmartauthservice.annotation.RequirePermission;
import id.ac.ui.cs.advprog.bidmartauthservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class PermissionInterceptorTest {

    @Mock
    private AuthService authService;

    @InjectMocks
    private PermissionInterceptor permissionInterceptor;

    private final PermissionHandler permissionHandler = new PermissionHandler();
    private final PlainHandler plainHandler = new PlainHandler();

    private HandlerMethod annotatedHandlerMethod;
    private HandlerMethod plainHandlerMethod;

    @BeforeEach
    void setUp() throws Exception {
        Method annotatedMethod = PermissionHandler.class.getDeclaredMethod("requiresBidPermission");
        Method plainMethod = PlainHandler.class.getDeclaredMethod("noAnnotation");
        annotatedHandlerMethod = new HandlerMethod(permissionHandler, annotatedMethod);
        plainHandlerMethod = new HandlerMethod(plainHandler, plainMethod);
    }

    @Test
    void preHandleShouldAllowNonHandlerMethod() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertTrue(permissionInterceptor.preHandle(request, response, new Object()));
    }

    @Test
    void preHandleShouldAllowHandlerWithoutAnnotation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertTrue(permissionInterceptor.preHandle(request, response, plainHandlerMethod));
    }

    @Test
    void preHandleShouldRejectMissingEmail() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean allowed = permissionInterceptor.preHandle(request, response, annotatedHandlerMethod);

        assertFalse(allowed);
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }

    @Test
    void preHandleShouldAllowAdminBypass() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("userEmail", "admin@test.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(authService.hasPermission("admin@test.com", "admin:*")).thenReturn(true);

        assertTrue(permissionInterceptor.preHandle(request, response, annotatedHandlerMethod));
    }

    @Test
    void preHandleShouldAllowSpecificPermission() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("userEmail", "buyer@test.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(authService.hasPermission("buyer@test.com", "admin:*")).thenReturn(false);
        when(authService.hasPermission("buyer@test.com", "bid:place")).thenReturn(true);

        assertTrue(permissionInterceptor.preHandle(request, response, annotatedHandlerMethod));
    }

    @Test
    void preHandleShouldRejectWhenPermissionMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("userEmail", "buyer@test.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(authService.hasPermission("buyer@test.com", "admin:*")).thenReturn(false);
        when(authService.hasPermission("buyer@test.com", "bid:place")).thenReturn(false);

        boolean allowed = permissionInterceptor.preHandle(request, response, annotatedHandlerMethod);

        assertFalse(allowed);
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }

    static class PermissionHandler {
        @RequirePermission("bid:place")
        public void requiresBidPermission() {
        }
    }

    static class PlainHandler {
        public void noAnnotation() {
        }
    }
}
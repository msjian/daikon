package org.talend.daikon.spring.auth.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class AuthExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthExceptionHandler.class);

    @ExceptionHandler
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException e) {
        if (SecurityContextHolder.getContext().getAuthentication().getClass().equals(AnonymousAuthenticationToken.class)) {
            LOGGER.debug("Handling AccessDeniedException for unauthorized request: {}", e.getMessage());
            HttpStatus status = HttpStatus.UNAUTHORIZED;
            ErrorResponse response = ErrorResponse.builder().status(status.value()).detail(status.getReasonPhrase()).build();
            return ResponseEntity.status(status).body(response);
        } else {
            LOGGER.debug("Handling AccessDeniedException with insufficient permissions: {}", e.getMessage());
            HttpStatus status = HttpStatus.FORBIDDEN;
            ErrorResponse response = ErrorResponse.builder().status(status.value()).detail(e.getMessage()).build();
            return ResponseEntity.status(status).body(response);
        }
    }

    @ExceptionHandler
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException e) {
        LOGGER.debug("Handling {} : {}", e.getClass().getName(), e.getMessage());
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String errorCode = HttpStatus.UNAUTHORIZED.getReasonPhrase();

        if (e instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) e).getError();
            errorCode = error.getErrorCode();
            if (error instanceof BearerTokenError) {
                status = ((BearerTokenError) error).getHttpStatus();
            }
        }

        ErrorResponse response = ErrorResponse.builder().title(errorCode).status(status.value()).build();
        return ResponseEntity.status(status).header(HttpHeaders.WWW_AUTHENTICATE, String.format("Bearer error=\"%s\"", errorCode))
                .body(response);
    }

}

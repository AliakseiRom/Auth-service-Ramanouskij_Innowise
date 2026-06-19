package com.innowise.authservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
public class RestResponseStatusExceptionResolver {

    @ExceptionHandler(EntityNotExistException.class)
    public ResponseEntity<Object> handleEntityNotExistException(EntityNotExistException ex, WebRequest request) {
        ErrorDetails errorDetails =
                new ErrorDetails(
                        HttpStatus.NOT_FOUND.value(),
                        ex.getMessage(),
                        request.getDescription(false)
                );
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Object> handleInvalidCredentialsException(InvalidCredentialsException ex, WebRequest request) {
        ErrorDetails errorDetails =
                new ErrorDetails(
                        HttpStatus.BAD_REQUEST.value(),
                        ex.getMessage(),
                        request.getDescription(false)
                );
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(
            AccessDeniedException ex,
            WebRequest request
    ) {
        ErrorDetails errorDetails = new ErrorDetails(
                HttpStatus.FORBIDDEN.value(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<Object> handleJwtException(JwtException ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(
                HttpStatus.UNAUTHORIZED.value(),
                ex.getMessage(),
                request.getDescription(false)
        );
        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }
}
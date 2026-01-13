package com.cybersecurity.application.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<String> handleSecurityBlock(SecurityException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("ACCESS DENIED: " + e.getMessage());
    }
}

package com.cybersecurity.application.aspect;

import com.cybersecurity.application.service.SecurityService;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

@Aspect
@Component
public class WafAspect {

    @Autowired
    private SecurityService securityService;

    @Before("execution(* com.cybersecurity.application.controller.SecureController.*(..))")
    public void inspectTraffic(JoinPoint joinPoint) throws Throwable {

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String ip = request.getRemoteAddr();
        String fingerprint = request.getHeader("X-Device-Fingerprint");
        String uri = request.getRequestURI();

        securityService.checkFingerprintAndBlock(ip, fingerprint);
        Object[] args = joinPoint.getArgs();

        for (Object arg : args) {
            if (arg instanceof String) {
                checkPayload(ip, fingerprint, (String) arg, uri);
            } else if (arg instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) arg;
                for (Object value : map.values()) {
                    if (value instanceof String) {
                        checkPayload(ip, fingerprint, (String) value, uri);
                    }
                }
            }

        }
    }

    private void checkPayload(String ip, String fingerprint, String content, String uri) {
        if (securityService.isMalicious(content)) {
            System.out.println("🚨 AOP DETECTED SQLi: " + content);

            securityService.logViolation(ip, fingerprint, content, uri);

            throw new SecurityException("BLOCKED: Malicious Payload Detected via AOP!");
        }
    }
}
package com.cybersecurity.application.aspect;

import com.cybersecurity.application.service.SecurityService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;

@RequiredArgsConstructor
@Aspect
@Component
public class LoggingAspect {

    private final SecurityService securityService;

    @AfterReturning(pointcut = "execution(* com.cybersecurity.application.controller.*.*(..)) " +
            "&& !execution(* com.cybersecurity.application.controller.AdminController.*(..))", returning = "result")
    public void logSuccessAccess(JoinPoint joinPoint, Object result) {
        try {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String ip = request.getRemoteAddr();
            String fingerprint = request.getHeader("X-Device-Fingerprint");
            String uri = request.getRequestURI();
            String methodName = joinPoint.getSignature().getName();

            String action = "Action: " + methodName;

            Object[] args = joinPoint.getArgs();
            if (args.length > 0) {
                action += " | Data: " + Arrays.toString(args);
            }

            securityService.logActivity(ip, fingerprint, uri, action);

        } catch (Exception e) {
            //
        }
    }
}
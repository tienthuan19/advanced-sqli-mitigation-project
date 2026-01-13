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

    // Pointcut: Áp dụng cho TẤT CẢ các method trong package controller
    // Nhưng CHỈ ÁP DỤNG cho các Controller "Secure" (để demo sự khác biệt)
    @Before("execution(* com.cybersecurity.application.controller.SecureController.*(..))")
    public void inspectTraffic(JoinPoint joinPoint) throws Throwable {

        // 1. Lấy Request hiện tại để lấy IP và Fingerprint
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String ip = request.getRemoteAddr();
        String fingerprint = request.getHeader("X-Device-Fingerprint");
        String uri = request.getRequestURI();

        // 2. Lấy toàn bộ tham số đầu vào của hàm Controller
        Object[] args = joinPoint.getArgs();

        for (Object arg : args) {
            if (arg instanceof String) {
                // Trường hợp 1: Tham số là String (ví dụ @RequestParam String query)
                checkPayload(ip, fingerprint, (String) arg, uri);
            } else if (arg instanceof Map) {
                // Trường hợp 2: Tham số là Map (ví dụ @RequestBody Map payload login)
                // Duyệt qua từng value trong Map để check
                Map<?, ?> map = (Map<?, ?>) arg;
                for (Object value : map.values()) {
                    if (value instanceof String) {
                        checkPayload(ip, fingerprint, (String) value, uri);
                    }
                }
            }
            // Trường hợp 3: Nếu là DTO (Object User, Product), bạn có thể dùng Reflection để quét các field String (nâng cao hơn)
        }
    }

    private void checkPayload(String ip, String fingerprint, String content, String uri) {
        if (securityService.isMalicious(content)) {
            System.out.println("🚨 AOP DETECTED SQLi: " + content);

            // Ghi log và check 3 strikes
            securityService.logViolation(ip, fingerprint, content, uri);

            // Ném Exception để chặn luồng xử lý (Spring sẽ trả về lỗi cho user)
            throw new SecurityException("BLOCKED: Malicious Payload Detected via AOP!");
        }
    }
}
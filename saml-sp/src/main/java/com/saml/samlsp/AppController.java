package com.saml.samlsp;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class AppController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/secure")
    public String secure() {
        return "secure";
    }

    @GetMapping(value="/welcome", params = "login")
    public String welcome() {
        return "welcome";
    }

    @EventListener
    public void handleContextStart(LogoutSuccessEvent lse) {
        System.out.println("#################### Logout ####################");
    }

}
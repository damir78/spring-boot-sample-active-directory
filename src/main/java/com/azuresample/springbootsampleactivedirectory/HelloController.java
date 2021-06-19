package com.azuresample.springbootsampleactivedirectory;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloController {

  @GetMapping("camunda")
  @ResponseBody
  @PreAuthorize("hasRole('ROLE_camunda')")
  public String camundaAdmin() {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Object principal = authentication.getPrincipal();
    DefaultOidcUser user = (DefaultOidcUser) principal;

    Map<String, Object> attributes = user.getAttributes();
    String preferredUsername = user.getAttribute("preferred_username");

    return "Hello Camunda Admin User [with roles]:" + preferredUsername + " "
        + authentication.getAuthorities() + ", attributes: " + attributes;
  }

  @GetMapping("group1")
  @ResponseBody
  @PreAuthorize("hasRole('ROLE_group1')")
  public String group1() {
    return "Hello Group 1 Users!";
  }

  @GetMapping("group2")
  @ResponseBody
  @PreAuthorize("hasRole('ROLE_group2')")
  public String group2() {
    return "Hello Group 2 Users!";
  }
}
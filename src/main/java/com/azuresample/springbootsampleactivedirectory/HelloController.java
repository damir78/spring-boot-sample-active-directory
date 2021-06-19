package com.azuresample.springbootsampleactivedirectory;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class HelloController {

  @GetMapping("camunda")
  @ResponseBody
  @PreAuthorize("hasRole('ROLE_camunda-admin')")
  public String camundaAdmin() {
    return "Hello Camunda Admin User!";
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

  @GetMapping("/")
  @ResponseBody
  public String root() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Object principal = authentication.getPrincipal();
    DefaultOidcUser user = (DefaultOidcUser) principal;

    Map<String, Object> attributes = user.getAttributes();
    String preferredUsername = user.getAttribute("preferred_username");

    StringBuilder result = new StringBuilder();
    result.append("<p>")
        .append("User [with roles]:").append(preferredUsername)
        .append(" ").append(authentication.getAuthorities())
        .append("</p>");
    result.append("<ul>");

    List<String> sortedKeys = new ArrayList<>(attributes.keySet());
    Collections.sort(sortedKeys);

    for (String key : sortedKeys) {
      result.append("<li>")
          .append(key).append(": ")
          .append(attributes.get(key))
          .append("</li>");
    }
    result.append("</ul>");
    return result.toString();
  }
}
package ru.javabegin.oauth2.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user") // базовый URI
public class UserController {

    @GetMapping("/data")
    public String user() {
        return "user data";
    }

}

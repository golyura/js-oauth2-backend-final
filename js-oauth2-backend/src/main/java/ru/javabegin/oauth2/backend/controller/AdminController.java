package ru.javabegin.oauth2.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin") // базовый URI
public class AdminController {

    // добавление
    @GetMapping("/data")
    public String admin() {
        return "admin data";
    }



}

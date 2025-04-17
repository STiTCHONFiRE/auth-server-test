package ru.stitchonfire.authserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("login")
    public String login() {
        return "index";
    }

//    @GetMapping("logout")
//    public String logout() {
//        return "logout";
//    }
}

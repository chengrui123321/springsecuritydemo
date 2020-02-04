package com.nowcoder.community.controller;

import com.nowcoder.community.entity.User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class HomeController {

    @RequestMapping(path = "/index", method = RequestMethod.GET)
    public String getIndexPage(Model model) {
        // 登陆成功会将用户信息保存在Spring Security 上下文中
        Object user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (user instanceof User) {
            model.addAttribute("user", user);
        }
        return "index";
    }

    @RequestMapping(path = "/discuss", method = RequestMethod.GET)
    public String getDiscussPage() {
        return "site/discuss";
    }

    @RequestMapping(path = "/letter", method = RequestMethod.GET)
    public String getLetterPage() {
        return "site/letter";
    }

    @RequestMapping(path = "/admin", method = RequestMethod.GET)
    public String getAdminPage() {
        return "site/admin";
    }

    @RequestMapping(path = "/loginPage", method = {RequestMethod.GET, RequestMethod.POST})
    public String getLoginPage() {
        return "site/login";
    }

    @GetMapping("/denied")
    public String deny() {
        return "error/404";
    }

}

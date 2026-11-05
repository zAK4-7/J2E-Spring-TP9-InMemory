package ma.fstg.security.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * MVC controller exposing the public, user and admin areas.
 */
@Controller
public class HomeController {

    @GetMapping("/")
    public String index(Authentication authentication, Model model) {
        model.addAttribute("username", authentication != null ? authentication.getName() : null);
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/user/dashboard")
    public String userDashboard(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        model.addAttribute("authorities", authentication.getAuthorities());
        return "user_dashboard";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        model.addAttribute("authorities", authentication.getAuthorities());
        return "admin_dashboard";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access_denied";
    }
}

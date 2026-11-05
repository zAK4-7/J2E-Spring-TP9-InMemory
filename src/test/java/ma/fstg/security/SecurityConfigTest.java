package ma.fstg.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the URL rules, the BCrypt encoding and the login flow.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private InMemoryUserDetailsManager userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void homePageShouldBePublic() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
    }

    @Test
    void userAreaShouldRedirectAnonymousVisitorsToLogin() throws Exception {
        mockMvc.perform(get("/user/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void userAreaShouldBeReachableByTheUserRole() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void adminAreaShouldRejectTheUserRole() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminAreaShouldBeReachableByTheAdminRole() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk());
    }

    @Test
    void passwordsMustBeStoredAsBcryptHashes() {
        UserDetails user = userDetailsService.loadUserByUsername("user");

        assertTrue(user.getPassword().startsWith("$2"), "BCrypt hashes start with $2");
        assertNotEquals("1111", user.getPassword());
        assertTrue(passwordEncoder.matches("1111", user.getPassword()));
    }

    @Test
    void validCredentialsShouldAuthenticate() throws Exception {
        mockMvc.perform(formLogin("/login").user("admin").password("1234"))
                .andExpect(authenticated().withUsername("admin"));
    }

    @Test
    void invalidCredentialsShouldStayUnauthenticated() throws Exception {
        mockMvc.perform(formLogin("/login").user("admin").password("wrong"))
                .andExpect(unauthenticated());
    }

    @Test
    void adminAccountShouldOwnBothRoles() {
        UserDetails admin = userDetailsService.loadUserByUsername("admin");

        assertEquals(2, admin.getAuthorities().size());
        assertTrue(admin.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
        assertTrue(admin.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }
}

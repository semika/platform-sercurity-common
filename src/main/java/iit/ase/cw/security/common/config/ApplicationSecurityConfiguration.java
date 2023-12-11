package iit.ase.cw.security.common.config;

import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.security.common.util.ThaproJwtTokenHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_SERVER_ENABLED, havingValue = "true")
public class ApplicationSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        ApplicationSecurityFilter filter = new ApplicationSecurityFilter(new ThaproJwtTokenHandler());
        http
                .authorizeHttpRequests((authz) -> authz
                        .anyRequest().authenticated()
                ).csrf((csrf) -> csrf.disable())
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

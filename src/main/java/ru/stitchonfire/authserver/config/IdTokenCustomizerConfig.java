package ru.stitchonfire.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class IdTokenCustomizerConfig {
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            /*if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue()) && context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {

            }*/
            context.getClaims()
                    .claim(
                            "authorities",
                            context.getPrincipal().getAuthorities()
                                    .stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .toList()
                    );
        };
    }
}

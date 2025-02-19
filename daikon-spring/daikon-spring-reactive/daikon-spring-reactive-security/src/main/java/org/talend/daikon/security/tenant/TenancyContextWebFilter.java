package org.talend.daikon.security.tenant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.talend.daikon.multitenant.context.DefaultTenancyContext;
import org.talend.daikon.multitenant.context.TenancyContext;
import org.talend.daikon.multitenant.provider.DefaultTenant;
import org.talend.daikon.spring.auth.common.model.userdetails.AuthUserDetails;

import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * Inspired by {@link org.springframework.security.web.server.context.ReactorContextWebFilter}
 */
public class TenancyContextWebFilter implements WebFilter {

    public static final String TENANT_ID = "tenant_id";

    private static final Logger LOGGER = LoggerFactory.getLogger(TenancyContextWebFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext().filter(c -> c.getAuthentication() != null)
                .map(SecurityContext::getAuthentication).flatMap(authentication -> chain.filter(exchange)
                        .subscriberContext(c -> c.hasKey(TenancyContext.class) ? c : withTenancyContext(c, authentication)));
    }

    private Context withTenancyContext(Context mainContext, Authentication authentication) {
        return mainContext.putAll(loadTenancyContext(authentication).as(ReactiveTenancyContextHolder::withTenancyContext));
    }

    public Mono<TenancyContext> loadTenancyContext(Authentication authentication) {
        final TenancyContext tenantContext = new DefaultTenancyContext();
        Object principal = authentication.getPrincipal();
        if (principal instanceof Jwt) {
            Jwt jwtPrincipal = (Jwt) principal;
            addTenant(tenantContext, jwtPrincipal.getClaimAsString(TENANT_ID), "JWT");
        } else if (authentication.getPrincipal() instanceof AuthUserDetails) {
            AuthUserDetails userDetails = (AuthUserDetails) principal;
            addTenant(tenantContext, userDetails.getTenantId(), "Auth0 token");
        } else if (principal instanceof OAuth2AuthenticatedPrincipal) {
            OAuth2AuthenticatedPrincipal oauth2Principal = (OAuth2AuthenticatedPrincipal) principal;
            addTenant(tenantContext, oauth2Principal.getAttribute(TENANT_ID), "Opaque token");
        } else {
            LOGGER.debug("Authentication not managed, cannot extract TenancyContext for '{}'", principal);
        }
        return Mono.justOrEmpty(tenantContext);
    }

    private void addTenant(TenancyContext tenantContext, String tenantId, String principalType) {
        LOGGER.debug("Populate TenancyContext for '{}' based on {}", tenantId, principalType);
        tenantContext.setTenant(new DefaultTenant(tenantId, null));
    }
}

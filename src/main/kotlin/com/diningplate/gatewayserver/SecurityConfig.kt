package com.diningplate.gatewayserver

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import reactor.core.publisher.Mono

/**
 * Realm roles enforced at the gateway. Names must match the realm roles defined in
 * `keycloak/realm/diningplate-realm.json` (they arrive in the JWT `realm_access.roles`
 * claim and are mapped to `ROLE_<name>` authorities).
 */
enum class Role {
    CUSTOMER,
    KITCHEN,
    DELIVERY,
    ADMIN,
}

/** Spreads roles into the `String` vararg expected by `hasAnyRole`. */
private fun roleNames(vararg roles: Role): Array<String> =
    roles.map { it.name }.toTypedArray()

/**
 * Turns the gateway into a stateless OAuth2 Resource Server.
 *
 * - Validates Bearer JWTs minted by Keycloak; no server-side session.
 * - Keys are fetched over the internal Docker network (jwk-set-uri -> keycloak:8080),
 *   while the `iss` claim is validated against the public issuer the browser sees
 *   (localhost:7080). This decouples the network location of the JWKS from the issuer
 *   value embedded in tokens.
 * - Keycloak realm roles (realm_access.roles) are mapped to ROLE_* authorities so the
 *   per-route `hasAnyRole(...)` rules below can enforce access. Spring's default
 *   converter only reads the `scope`/`scp` claim, so a custom converter is required.
 */
@Configuration
@EnableWebFluxSecurity
class SecurityConfig(
    @param:Value("\${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private val jwkSetUri: String,
    @param:Value("\${diningplate.security.public-issuer-uri}")
    private val publicIssuerUri: String,
    @param:Value("\${diningplate.security.cors.allowed-origins:http://localhost:5173}")
    private val allowedOrigins: List<String>,
) {

    private val orderApi = "/diningplate/order-service/api/v1"

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeExchange { exchanges ->
                exchanges
                    .pathMatchers("/actuator/**").permitAll()
                    // Menu: anyone authenticated may browse; only ADMIN/KITCHEN may create.
                    .pathMatchers(HttpMethod.GET, "$orderApi/menu").authenticated()
                    .pathMatchers(HttpMethod.POST, "$orderApi/menu").hasAnyRole(*roleNames(Role.ADMIN, Role.KITCHEN))
                    // Orders.
                    .pathMatchers(HttpMethod.POST, "$orderApi/orders").hasAnyRole(*roleNames(Role.CUSTOMER, Role.ADMIN))
                    .pathMatchers(HttpMethod.GET, "$orderApi/orders")
                    .hasAnyRole(*roleNames(Role.KITCHEN, Role.ADMIN, Role.DELIVERY))
                    .pathMatchers(HttpMethod.GET, "$orderApi/orders/*")
                    .hasAnyRole(*roleNames(Role.CUSTOMER, Role.KITCHEN, Role.ADMIN, Role.DELIVERY))
                    .pathMatchers(HttpMethod.DELETE, "$orderApi/orders/*")
                    .hasAnyRole(*roleNames(Role.CUSTOMER, Role.KITCHEN, Role.ADMIN))
                    .pathMatchers(HttpMethod.PATCH, "$orderApi/orders/*/status")
                    .hasAnyRole(*roleNames(Role.KITCHEN, Role.ADMIN, Role.DELIVERY))
                    .anyExchange().authenticated()
            }
            .oauth2ResourceServer { oauth2 ->
                oauth2.jwt { jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor()) }
            }
        return http.build()
    }

    /**
     * Fetch the JWKS from the internal URL but validate the issuer claim against the
     * public-facing issuer URL that ends up in browser-issued tokens.
     */
    @Bean
    fun reactiveJwtDecoder(): ReactiveJwtDecoder {
        val decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build()
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(publicIssuerUri))
        return decoder
    }

    /** Maps Keycloak realm roles (`realm_access.roles`) to `ROLE_<role>` authorities. */
    private fun grantedAuthoritiesExtractor(): Converter<Jwt, Mono<AbstractAuthenticationToken>> {
        val realmRolesConverter = Converter<Jwt, Collection<GrantedAuthority>> { jwt ->
            val realmAccess = jwt.getClaimAsMap("realm_access") ?: emptyMap()

            @Suppress("UNCHECKED_CAST")
            val roles = realmAccess["roles"] as? List<String> ?: emptyList()
            roles.map { SimpleGrantedAuthority("ROLE_$it") }
        }
        val jwtConverter = JwtAuthenticationConverter().apply {
            // Keep Spring's default scope authorities and add realm roles on top.
            setJwtGrantedAuthoritiesConverter { jwt ->
                buildList {
                    addAll(JwtGrantedAuthoritiesConverter().convert(jwt) ?: emptyList())
                    addAll(realmRolesConverter.convert(jwt) ?: emptyList())
                }
            }
        }
        return ReactiveJwtAuthenticationConverterAdapter(jwtConverter)
    }

    private fun corsConfigurationSource(): CorsConfigurationSource {
        val config = CorsConfiguration().apply {
            allowedOrigins = this@SecurityConfig.allowedOrigins
            allowedMethods = listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
            allowedHeaders = listOf("*")
            allowCredentials = true
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/**", config)
        }
    }
}

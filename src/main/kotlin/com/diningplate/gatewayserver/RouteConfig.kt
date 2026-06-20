package com.diningplate.gatewayserver

import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class RouteConfig {

	// Custom "diningplate" routing: requests under /diningplate/<service>/...
	// have the "diningplate" segment stripped and are forwarded to the
	// load-balanced service discovered through Eureka (lb://<SERVICE>).
	//
	// Coexists with the discovery locator (lower-case service ids) configured
	// centrally in gatewayserver.yaml.
	@Bean
	fun diningplateRoutes(builder: RouteLocatorBuilder): RouteLocator =
		builder.routes()
			.route("order-service") { r ->
				r.path("/diningplate/order-service/**")
					.filters { f ->
						f.rewritePath("/diningplate/(?<segment>.*)", "/\${segment}")
					}
					.uri("lb://ORDER-SERVICE")
			}
			.build()
}

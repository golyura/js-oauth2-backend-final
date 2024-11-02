package ru.javabegin.oauth2.backend.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.javabegin.oauth2.backend.exception.OAuth2ExceptionHandler;
import ru.javabegin.oauth2.backend.utils.KCRoleConverter;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration // данный класс будет считан как конфиг для spring контейнера
@EnableWebSecurity // включает механизм защиты адресов, которые настраиваются в SecurityFilterChain
// в старых версиях spring security нужно было наследовать от спец. класса WebSecurityConfigurerAdapter
// Подробнее https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
@EnableMethodSecurity(prePostEnabled = true) // включение механизма для защиты методов по ролям
// исключить авто конфигурация для подключения к БД
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class, DataSourceTransactionManagerAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
public class SpringSecurityConfig {

    @Value("${client.url}")
    private String clientURL; // клиентский URL

    // создается спец. бин, который отвечает за настройки запросов по http (метод вызывается автоматически) Spring контейнером
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // конвертер для настройки spring security
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        // подключаем конвертер ролей
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KCRoleConverter());


        http.authorizeHttpRequests((requests) -> requests
//                        .requestMatchers("*").permitAll()
                        .requestMatchers("/admin/*").hasRole("admin")
                        .requestMatchers("/auth/*").hasRole("user")
                        .anyRequest().authenticated())
                // отключаем встроенную защиту от CSRF атак, т.к. используем свою, из OAUTH2
                .csrf(AbstractHttpConfigurer::disable)
                // разрешает выполнять OPTIONS запросы от клиента (preflight запросы) без авторизации
                .cors(withDefaults())
                .oauth2ResourceServer(
                        oauth2ResourceServer -> oauth2ResourceServer
                                .jwt(jwt ->
                                        jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)
                                )
                                // важно добавлять этот класс после jwt (не раньше), чтобы он применился именно к библиотеке oauth2
                                .authenticationEntryPoint(new OAuth2ExceptionHandler())
                );


////         все сетевые настройки
//        http.authorizeRequests()
//                .requestMatchers("/test/login").permitAll()
////                .antMatchers("/test/login").permitAll() // анонимный пользователь сможет выполнять запросы только по этим URI
//                .anyRequest().authenticated(); // остальной API будет доступен только аутентифицированным пользователям

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(clientURL));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}

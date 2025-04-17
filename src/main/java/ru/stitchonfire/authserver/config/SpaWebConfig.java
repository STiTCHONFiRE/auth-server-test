package ru.stitchonfire.authserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SpaWebConfig implements WebMvcConfigurer {

    // Отдаём статику (js, css, картинки) из /static как обычно
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // 1) корень
        registry
                .addViewController("/")
                .setViewName("forward:/index.html");

        // 2) одноуровневые пути без “.” в имени и не начинающиеся с login|logout|oauth2|error
        registry
                .addViewController("/{path:^(?!login|logout|oauth2|error)[^\\.]+}")
                .setViewName("forward:/index.html");

        // 3) более глубокие пути, но первый сегмент тоже не login|logout|oauth2|error
        registry
                .addViewController("/{path:^(?!login|logout|oauth2|error)[^\\.]+}/**")
                .setViewName("forward:/index.html");
    }

}

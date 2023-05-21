package com.example.application.configuration;

import com.example.application.annotation.EncryptedValue;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Data
@Configuration
public class MySqlConfiguration {

    @Value("${mysql.url}")
    private String url;

    @Value("${mysql.username}")
    @EncryptedValue
    private String username;

    @Value("${mysql.password}")
    @EncryptedValue
    private String password;

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);
        return dataSource;
    }
}

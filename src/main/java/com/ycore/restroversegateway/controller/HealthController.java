package com.ycore.restroversegateway.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/health")
@Slf4j
public class HealthController {

    @GetMapping("")
    public ResponseEntity<String> status(){
        log.info("Health check requested");
        return ResponseEntity.ok("OK");
    }

}

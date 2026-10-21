package com.tracepcap.analysis.controller;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.tracepcap.analysis.service.PacketDissectionService;
import com.tracepcap.config.security.AuthEnabledSecurityConfig;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
    controllers = PacketDissectionController.class,
    properties = {
      "tracepcap.auth.enabled=true",
      "tracepcap.auth.issuer-uri=https://auth.example.invalid",
      "tracepcap.jackson.max-string-length=20000000"
    })
@Import(AuthEnabledSecurityConfig.class)
class PacketDissectionSecurityTest {
  @Autowired MockMvc mvc;
  @MockBean PacketDissectionService service;
  @MockBean JwtDecoder jwtDecoder;

  @Test
  void protectedDissectionRouteRejectsUnauthenticatedRequestsBeforeDecoderRuns() throws Exception {
    mvc.perform(get("/conversations/detail/" + UUID.randomUUID() + "/packets/1/dissection"))
        .andExpect(status().isUnauthorized());
    verifyNoInteractions(service);
  }
}

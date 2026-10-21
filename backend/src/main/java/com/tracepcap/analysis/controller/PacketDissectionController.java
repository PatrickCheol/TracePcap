package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.PacketDissectionResponse;
import com.tracepcap.analysis.service.PacketDissectionService;
import io.swagger.v3.oas.annotations.Operation;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/conversations/detail")
@RequiredArgsConstructor
public class PacketDissectionController {
  private final PacketDissectionService dissectionService;

  @GetMapping("/{conversationId}/packets/{packetNumber}/dissection")
  @Operation(
      summary = "Decode one original frame with protocol fields, NAS bit masks and raw bytes")
  public ResponseEntity<PacketDissectionResponse> dissect(
      @PathVariable UUID conversationId, @PathVariable long packetNumber) {
    return ResponseEntity.ok(dissectionService.dissect(conversationId, packetNumber));
  }
}

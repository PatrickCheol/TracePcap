package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** Bit masks come from the installed decoder's registry, never guessed from field names. */
@Component
public class TsharkFieldRegistry {
  public record Metadata(String bitmask, String description) {}

  private final TsharkDissectionRunner runner;
  private volatile Map<String, Metadata> fields;

  public TsharkFieldRegistry(TsharkDissectionRunner runner) {
    this.runner = runner;
  }

  public synchronized Map<String, Metadata> fields() throws IOException {
    return fields(Duration.ofSeconds(30));
  }

  public synchronized Map<String, Metadata> fields(Duration timeout) throws IOException {
    if (fields == null) {
      var output = runner.run(List.of("tshark", "-G", "fields"), 96 * 1024 * 1024, timeout);
      fields = parse(new String(output.stdout(), StandardCharsets.UTF_8));
    }
    return fields;
  }

  static Map<String, Metadata> parse(String registry) throws IOException {
    Map<String, Metadata> result = new HashMap<>();
    try (var reader = new BufferedReader(new StringReader(registry))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (!line.startsWith("F\t")) continue;
        String[] columns = line.split("\t", -1);
        if (columns.length < 7 || columns[2].isBlank()) continue;
        String mask = columns[6];
        if (!mask.matches("0x[0-9a-fA-F]+") || mask.matches("0x0+")) mask = null;
        String description = columns.length > 7 && !columns[7].isBlank() ? columns[7] : null;
        if (mask != null || description != null) {
          result.putIfAbsent(columns[2], new Metadata(mask, description));
        }
      }
    }
    return Map.copyOf(result);
  }
}

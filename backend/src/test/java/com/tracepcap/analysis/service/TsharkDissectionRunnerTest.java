package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class TsharkDissectionRunnerTest {
  @Test
  void timesOutAndKillsDecoder() throws Exception {
    Process process = process(new byte[0]);
    when(process.waitFor(anyLong(), any())).thenReturn(false);
    var runner = runner(process);
    assertThatThrownBy(() -> runner.run(List.of("tshark"), 100, Duration.ofMillis(5)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("timed out");
    verify(process).destroyForcibly();
  }

  @Test
  void boundsOutputEvenIfDecoderWouldOtherwiseSucceed() throws Exception {
    Process process = process(new byte[100]);
    when(process.waitFor(anyLong(), any())).thenReturn(true);
    assertThatThrownBy(() -> runner(process).run(List.of("tshark"), 8, Duration.ofSeconds(1)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("output limit");
    verify(process, atLeastOnce()).destroyForcibly();
  }

  static Process process(byte[] output) {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(output));
    when(process.getErrorStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(process.descendants()).thenAnswer(invocation -> Stream.empty());
    return process;
  }

  static TsharkDissectionRunner runner(Process process) {
    return new TsharkDissectionRunner() {
      @Override
      protected Process start(List<String> arguments) {
        return process;
      }
    };
  }
}

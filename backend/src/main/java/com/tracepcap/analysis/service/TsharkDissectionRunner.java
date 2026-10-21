package com.tracepcap.analysis.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.stereotype.Component;

/** Executes fixed argument vectors without a shell, with bounded output and wall time. */
@Component
public class TsharkDissectionRunner {
  public record Output(byte[] stdout, byte[] stderr) {}

  public Output run(List<String> arguments, int maxBytes, Duration timeout) throws IOException {
    Process process = start(arguments);
    try (var readers = Executors.newVirtualThreadPerTaskExecutor()) {
      var stdout = readers.submit(() -> readBounded(process.getInputStream(), maxBytes, process));
      var stderr = readers.submit(() -> readBounded(process.getErrorStream(), 65_536, process));
      try {
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
          throw new IOException("Packet decoder timed out. Try a smaller capture.");
        }
        byte[] output = stdout.get(2, TimeUnit.SECONDS);
        byte[] errors = stderr.get(2, TimeUnit.SECONDS);
        if (process.exitValue() != 0) {
          // Do not echo decoder stderr: it can contain capture content and local paths.
          throw new IOException(
              "Packet decoder could not read this capture (exit " + process.exitValue() + ").");
        }
        return new Output(output, errors);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Packet decoding interrupted.", e);
      } catch (ExecutionException e) {
        throw new IOException(
            "Packet decoder exceeded the output limit or could not read its output.", e);
      } catch (TimeoutException e) {
        throw new IOException("Packet decoder output timed out.", e);
      } finally {
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        try {
          process.getInputStream().close();
          process.getErrorStream().close();
          process.getOutputStream().close();
        } catch (IOException ignored) {
          // The process may already have closed its pipes.
        }
      }
    }
  }

  protected Process start(List<String> arguments) throws IOException {
    return new ProcessBuilder(arguments).start();
  }

  private static byte[] readBounded(InputStream stream, int maxBytes, Process process)
      throws IOException {
    try (stream;
        var output = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = stream.read(buffer)) != -1) {
        if ((long) output.size() + read > maxBytes) {
          process.destroyForcibly();
          throw new IOException("Decoder output limit exceeded.");
        }
        output.write(buffer, 0, read);
      }
      return output.toByteArray();
    }
  }
}

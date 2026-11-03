// QA-only bounded direct-process capture. No process enumeration or PID reopen.
// Windows compilation/execution remains NOT_RUN until the reviewed ARM job.
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public sealed class D5CaptureReceipt {
    public bool Started { get; internal set; }
    public bool Exited { get; internal set; }
    public int? ExitCode { get; internal set; }
    public bool TimedOut { get; internal set; }
    public bool KillAttempted { get; internal set; }
    public bool KillSucceeded { get; internal set; }
    public bool RetainedHandleCaptured { get; internal set; }
    public bool StdoutEof { get { return Volatile.Read(ref stdoutEof) != 0; } internal set { Interlocked.Exchange(ref stdoutEof, value ? 1 : 0); } }
    public bool StderrEof { get { return Volatile.Read(ref stderrEof) != 0; } internal set { Interlocked.Exchange(ref stderrEof, value ? 1 : 0); } }
    public bool PipeFailure { get { return Volatile.Read(ref pipeFailure) != 0; } internal set { Interlocked.Exchange(ref pipeFailure, value ? 1 : 0); } }
    public bool Overflow { get { return Volatile.Read(ref overflow) != 0; } }
    public long StdoutObservedBytes { get { return Interlocked.Read(ref stdoutObserved); } }
    public long StderrObservedBytes { get { return Interlocked.Read(ref stderrObserved); } }
    public long ElapsedMs { get; internal set; }
    public long CaptureElapsedMs { get; internal set; }
    public string FailureCode { get; internal set; }
    internal int overflow;
    internal int stdoutEof, stderrEof, pipeFailure;
    internal long stdoutObserved, stderrObserved;
}

public static class D5Capture {
    private static async Task Pump(Stream input, FileStream output, int limit,
            D5CaptureReceipt receipt, bool stdout, CancellationToken token) {
        byte[] buffer = new byte[65536]; long saved = 0;
        try {
            while (true) {
                int count = await input.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
                if (count == 0) { if (stdout) receipt.StdoutEof = true; else receipt.StderrEof = true; break; }
                if (stdout) Interlocked.Add(ref receipt.stdoutObserved, count);
                else Interlocked.Add(ref receipt.stderrObserved, count);
                int keep = (int)Math.Min(count, Math.Max(0, limit - saved));
                if (keep > 0) { await output.WriteAsync(buffer, 0, keep, token).ConfigureAwait(false); saved += keep; }
                if (keep < count) Interlocked.Exchange(ref receipt.overflow, 1);
            }
            await output.FlushAsync(token).ConfigureAwait(false);
        } catch (OperationCanceledException) { receipt.PipeFailure = true; }
          catch (ObjectDisposedException) { receipt.PipeFailure = true; }
          catch (IOException) { receipt.PipeFailure = true; }
          catch { receipt.PipeFailure = true; }
        finally { output.Dispose(); }
    }

    public static D5CaptureReceipt Run(string executable, string[] arguments,
            string workingDirectory, Dictionary<string,string> environment,
            string stdoutPath, string stderrPath, int timeoutMs, int stdoutLimit, int stderrLimit) {
        // Outer workflow bounds this supervisor at 740 s. Its product call
        // independently hardcodes <=650 s; the two scopes must not be confused.
        if (timeoutMs < 1 || timeoutMs > 760000 || stdoutLimit < 1 || stdoutLimit > 16777216 ||
                stderrLimit < 1 || stderrLimit > 16777216) throw new ArgumentException("D5_CAPTURE_LIMIT");
        var receipt = new D5CaptureReceipt();
        var watch = Stopwatch.StartNew();
        var start = new ProcessStartInfo(executable) {
            UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = workingDirectory,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.Environment.Clear();
        foreach (var pair in environment) start.Environment.Add(pair.Key, pair.Value);
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using (var process = new Process { StartInfo = start })
        using (var cancel = new CancellationTokenSource()) {
            FileStream stdout = null, stderr = null;
            Task outTask = null, errTask = null;
            try {
                stdout = new FileStream(stdoutPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, true);
                stderr = new FileStream(stderrPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, true);
                if (!process.Start()) { receipt.FailureCode = "D5_PROCESS_NOT_STARTED"; return receipt; }
                receipt.Started = true;
                // Force acquisition and retention of this exact Process object's
                // native handle before observing a deadline or issuing Kill.
                receipt.RetainedHandleCaptured = process.Handle != IntPtr.Zero;
                process.StandardInput.Close();
                outTask = Pump(process.StandardOutput.BaseStream, stdout, stdoutLimit, receipt, true, cancel.Token); stdout = null;
                errTask = Pump(process.StandardError.BaseStream, stderr, stderrLimit, receipt, false, cancel.Token); stderr = null;
                while (true) {
                    int left = (int)Math.Max(0, timeoutMs - watch.ElapsedMilliseconds);
                    if (left == 0) { receipt.TimedOut = true; break; }
                    if (process.WaitForExit(Math.Min(left, 50))) {
                        receipt.Exited = true;
                        receipt.TimedOut = watch.ElapsedMilliseconds > timeoutMs;
                        break;
                    }
                    if (receipt.Overflow || receipt.PipeFailure) break;
                }
                if (!receipt.Exited) {
                    receipt.KillAttempted = true;
                    try {
                        if (!receipt.RetainedHandleCaptured) throw new InvalidOperationException();
                        process.Kill(false); // Exact cached process only, NEVER descendants.
                        receipt.KillSucceeded = true;
                    } catch { receipt.FailureCode = "D5_EXACT_PROCESS_KILL_UNCONFIRMED"; }
                    receipt.Exited = process.WaitForExit(5000);
                }
                receipt.ElapsedMs = watch.ElapsedMilliseconds;
                if (receipt.Exited) receipt.ExitCode = process.ExitCode;
                // Own-process exit does not imply pipe EOF or descendant/Job
                // closure. The timed overload is mandatory even after exit.
                try { if (!Task.WaitAll(new Task[] { outTask, errTask }, 2000)) receipt.PipeFailure = true; }
                catch { receipt.PipeFailure = true; }
                if (!receipt.StdoutEof || !receipt.StderrEof) {
                    receipt.PipeFailure = true; cancel.Cancel();
                    try { process.StandardOutput.Close(); } catch { }
                    try { process.StandardError.Close(); } catch { }
                    try { Task.WaitAll(new Task[] { outTask, errTask }, 1000); } catch { }
                }
            } catch {
                receipt.FailureCode = "D5_PROCESS_CAPTURE_FAILED";
                if (receipt.Started && !receipt.Exited && receipt.RetainedHandleCaptured) {
                    receipt.KillAttempted = true;
                    try { process.Kill(false); receipt.KillSucceeded = true; } catch { }
                    try { receipt.Exited = process.WaitForExit(5000); if (receipt.Exited) receipt.ExitCode = process.ExitCode; } catch { }
                }
            } finally {
                if (receipt.ElapsedMs == 0) receipt.ElapsedMs = watch.ElapsedMilliseconds;
                cancel.Cancel();
                if (stdout != null) stdout.Dispose(); if (stderr != null) stderr.Dispose();
                // Disposal closes our pipe handles; no unbounded task wait.
                if (receipt.Started) { try { process.StandardOutput.Close(); } catch { } try { process.StandardError.Close(); } catch { } }
                receipt.CaptureElapsedMs = watch.ElapsedMilliseconds;
            }
        }
        return receipt;
    }
}

public static class D5OwnedDirectory {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    private static extern bool CreateDirectoryW(string name, IntPtr securityAttributes);
    public static void CreateFresh(string name) {
        if (!CreateDirectoryW(name, IntPtr.Zero)) throw new IOException("D5_FRESH_DIRECTORY_REQUIRED");
        if ((File.GetAttributes(name) & FileAttributes.ReparsePoint) != 0) throw new IOException("D5_DIRECTORY_REPARSE");
    }
}

public static class D5PublicKey {
    private static string Hash(byte[] data) { return Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(); }
    public static bool Verify(byte[] pem) {
        if (pem.Length != 625 || Hash(pem) != "6443fc9c6c7369ca1931fd05ffcc56bb01a4ef086e7f83ddaac7da4118072cdb") return false;
        using (var rsa = RSA.Create()) {
            rsa.ImportFromPem(Encoding.ASCII.GetString(pem));
            return rsa.KeySize == 3072 && Hash(rsa.ExportSubjectPublicKeyInfo()) == "a7b0e9a0f1fe0a908da8aa9798dc4d8a9d2cec7526015e67aaa0989dcb30356b";
        }
    }
}

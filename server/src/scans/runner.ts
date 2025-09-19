import type { Response } from 'express';
import { logger } from '../config/logging.js';
import { updateScanStatus, type Scan } from '../db/repositories/scans.js';
import Docker from 'dockerode';
import fs from 'fs';
import path from 'path';
import { config } from '../config/env.js';
import { createScanArtifact } from '../db/repositories/scan_artifacts.js';
import { createFinding } from '../db/repositories/findings.js';

export type ScanProgressEvent = {
  type: 'log' | 'status' | 'done' | 'error';
  message?: string;
  status?: Scan['status'];
  timestamp: string;
};

type RunOptions = {
  profile?: string | null;
  scanners?: string[];
  scope?: 'org' | 'repo';
  repo?: string;
};

class InMemoryScanRunner {
  private logs: Map<string, string[]> = new Map();
  private subscribers: Map<string, Set<Response>> = new Map();
  private timers: Map<string, NodeJS.Timeout[]> = new Map();
  private docker = new Docker({ socketPath: '/var/run/docker.sock' });

  subscribe(scanId: string, res: Response): void {
    if (!this.subscribers.has(scanId)) this.subscribers.set(scanId, new Set());
    this.subscribers.get(scanId)!.add(res);

    // Send existing logs to late subscribers
    const existing = this.logs.get(scanId) || [];
    for (const line of existing) {
      this.emitSse(res, { type: 'log', message: line, timestamp: new Date().toISOString() });
    }
  }

  unsubscribe(scanId: string, res: Response): void {
    this.subscribers.get(scanId)?.delete(res);
  }

  private broadcast(scanId: string, event: ScanProgressEvent): void {
    const subs = this.subscribers.get(scanId);
    if (!subs || subs.size === 0) return;
    for (const res of subs) this.emitSse(res, event);
  }

  private emitSse(res: Response, event: ScanProgressEvent): void {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }

  private appendLog(scanId: string, line: string): void {
    if (!this.logs.has(scanId)) this.logs.set(scanId, []);
    this.logs.get(scanId)!.push(line);
  }

  async start(scan: Scan, opts?: RunOptions): Promise<void> {
    // If a scanner image is configured, run the real Shai-Hulud scanner in Docker.
    if (config.scannerImage) {
      return this.startWithDocker(scan, opts);
    }

    // Fallback: simulated scan lifecycle
    const scanId = scan.id;
    this.appendLog(scanId, `Queued scan ${scanId}`);
    this.broadcast(scanId, { type: 'status', status: 'queued', timestamp: new Date().toISOString() });

    await updateScanStatus(scanId, 'running', { started_at: new Date() });
    const profile = opts?.profile || 'balanced';
    const sel = (opts?.scanners && opts.scanners.length) ? opts.scanners.join(',') : 'all';
    const scope = opts?.scope || 'org';
    const repo = opts?.repo || '';
    this.appendLog(scanId, `Starting scan... profile=${profile} scanners=${sel} scope=${scope}${repo ? ` repo=${repo}` : ''}`);
    this.broadcast(scanId, { type: 'status', status: 'running', timestamp: new Date().toISOString() });

    const steps = [
      'Initializing environment',
      'Enumerating targets',
      'Executing scanners (Phase 1 placeholder)',
      'Aggregating results',
      'Finalizing'
    ];
    const timers: NodeJS.Timeout[] = [];
    this.timers.set(scanId, timers);
    steps.forEach((msg, idx) => {
      const t = setTimeout(() => {
        this.appendLog(scanId, msg);
        this.broadcast(scanId, { type: 'log', message: msg, timestamp: new Date().toISOString() });
      }, (idx + 1) * 750);
      timers.push(t);
    });
    const doneTimer = setTimeout(async () => {
      try {
        await updateScanStatus(scanId, 'success', { finished_at: new Date() });
        this.appendLog(scanId, 'Scan completed successfully');
        this.broadcast(scanId, { type: 'done', message: 'success', timestamp: new Date().toISOString() });
        logger.info({ scanId }, 'Scan finished');
      } catch (err) {
        logger.error({ err, scanId }, 'Failed to finalize scan');
        this.broadcast(scanId, { type: 'error', message: 'finalize_failed', timestamp: new Date().toISOString() });
      } finally {
        this.clearTimers(scanId);
      }
    }, (steps.length + 2) * 750);
    timers.push(doneTimer);
  }

  private async startWithDocker(scan: Scan, opts?: RunOptions): Promise<void> {
    const scanId = scan.id;
    this.appendLog(scanId, `Queued scan ${scanId}`);
    this.broadcast(scanId, { type: 'status', status: 'queued', timestamp: new Date().toISOString() });
    await updateScanStatus(scanId, 'running', { started_at: new Date() });
    const profile = opts?.profile || 'balanced';
    const only = (opts?.scanners && opts.scanners.length) ? opts.scanners.join(',') : undefined;
    const scope = opts?.scope || 'org';
    const repo = opts?.repo;
    this.appendLog(scanId, `Starting orchestrator (Docker)... profile=${profile}${only ? ` only=${only}` : ''} scope=${scope}${repo ? ` repo=${repo}` : ''}`);
    this.broadcast(scanId, { type: 'status', status: 'running', timestamp: new Date().toISOString() });

    // Prepare output directory bind
    const containerRunsPath = '/workspace/runs';
    const scanDir = path.join(containerRunsPath, scanId);
    try { fs.mkdirSync(scanDir, { recursive: true }); } catch {}
    const hostRunsDir = await this.getHostRunsDir(containerRunsPath);
    if (!hostRunsDir) {
      this.appendLog(scanId, 'Failed to resolve host runs directory for bind mount; falling back to simulation');
      return this.start(scan); // fallback
    }

    const binds = [`${path.join(hostRunsDir, scanId)}:/work/reports`];

    const env = [
      `GITHUB_TOKEN=${process.env.GITHUB_TOKEN || ''}`,
      `GITHUB_ORG=${process.env.GITHUB_ORG || ''}`,
      `GITHUB_API=${process.env.GITHUB_API || 'https://api.github.com'}`,
      'REPORT_DIR=/work/reports'
    ];

    try {
      await this.ensureImage(config.scannerImage!);
      const cmd: string[] = ['orchestrate_scans.py', '--profile', profile];
      if (only) {
        cmd.push('--only', only);
      }
      if (scope === 'repo' && repo) {
        cmd.push('--repo', repo);
      } else {
        cmd.push('--org', process.env.GITHUB_ORG || '');
      }
      const container = await this.docker.createContainer({
        Image: config.scannerImage!,
        Entrypoint: ['python'],
        Cmd: cmd,
        Env: env,
        WorkingDir: '/app',
        Tty: true,
        HostConfig: { Binds: binds, AutoRemove: true }
      });

      const stream = await container.attach({ stream: true, stdout: true, stderr: true });
      stream.on('data', (chunk: Buffer) => {
        const text = chunk.toString('utf-8');
        text.split(/\r?\n/).filter(Boolean).forEach((line: string) => {
          this.appendLog(scanId, line);
          this.broadcast(scanId, { type: 'log', message: line, timestamp: new Date().toISOString() });
        });
      });

      await container.start();
      const result = await container.wait();
      const code = (result?.StatusCode ?? 1);

      if (code !== 0) {
        this.appendLog(scanId, `Scanner exited with code ${code}`);
        await updateScanStatus(scanId, 'failed', { finished_at: new Date() });
        this.broadcast(scanId, { type: 'error', message: `exit_${code}`, timestamp: new Date().toISOString() });
        this.broadcast(scanId, { type: 'done', message: 'failed', timestamp: new Date().toISOString() });
        return;
      }

      // Persist artifacts & finding summary
      let summaryPath = path.join(scanDir, 'shaihulu_summary.md');
      try {
        if (!fs.existsSync(summaryPath)) {
          const alt = path.join(scanDir, 'shaihulud_reports', 'shaihulu_summary.md');
          if (fs.existsSync(alt)) summaryPath = alt;
        }
        if (fs.existsSync(summaryPath)) {
          const stat = fs.statSync(summaryPath);
          await createScanArtifact({
            scan_id: scanId,
            name: 'shaihulu_summary.md',
            path: summaryPath,
            mime: 'text/markdown',
            size_bytes: stat.size,
          });
          await this.parseAndPersistShaihulud(scan, summaryPath);
          await updateScanStatus(scanId, 'success', { finished_at: new Date(), summary_md_path: summaryPath });
        } else {
          await updateScanStatus(scanId, 'success', { finished_at: new Date() });
        }
        this.appendLog(scanId, 'Scan completed successfully');
        this.broadcast(scanId, { type: 'done', message: 'success', timestamp: new Date().toISOString() });
      } catch (err) {
        logger.error({ err, scanId }, 'Post-scan processing failed');
        this.broadcast(scanId, { type: 'error', message: 'post_processing_failed', timestamp: new Date().toISOString() });
        await updateScanStatus(scanId, 'failed', { finished_at: new Date() });
        this.broadcast(scanId, { type: 'done', message: 'failed', timestamp: new Date().toISOString() });
      }
    } catch (err) {
      logger.error({ err, scanId }, 'Failed to start scanner container');
      this.appendLog(scanId, 'Failed to start scanner container');
      await updateScanStatus(scanId, 'failed', { finished_at: new Date() });
      this.broadcast(scanId, { type: 'error', message: 'container_start_failed', timestamp: new Date().toISOString() });
      this.broadcast(scanId, { type: 'done', message: 'failed', timestamp: new Date().toISOString() });
    }
  }

  private async ensureImage(image: string): Promise<void> {
    try {
      await this.docker.getImage(image).inspect();
      return;
    } catch {
      logger.info({ image }, 'Scanner image not found locally. Pulling...');
      await new Promise<void>((resolve, reject) => {
        this.docker.pull(image, (err: any, stream: any) => {
          if (err) return reject(err);
          // followProgress is not typed in dockerode defs under NodeNext, cast to any
          (this.docker as any).modem.followProgress(stream, (err2: any) => {
            if (err2) return reject(err2);
            resolve();
          });
        });
      });
      logger.info({ image }, 'Scanner image pulled');
    }
  }

  private async getHostRunsDir(containerRunsPath: string): Promise<string | null> {
    try {
      const selfId = process.env.HOSTNAME || '';
      const info = await this.docker.getContainer(selfId).inspect();
      const m = (info.Mounts || []).find((x: any) => x.Destination === containerRunsPath);
      return m?.Source || null;
    } catch (e) {
      logger.warn({ e }, 'Failed to inspect container for runs mount');
      return null;
    }
  }

  private async parseAndPersistShaihulud(scan: Scan, summaryPath: string): Promise<void> {
    try {
      const content = fs.readFileSync(summaryPath, 'utf-8');
      const hasHits = /\n- \{/.test(content);
      await createFinding({
        project_id: scan.project_id,
        scan_id: scan.id,
        source: 'custom',
        title: hasHits ? 'Shai-Hulud indicators detected' : 'No Shai-Hulud indicators detected',
        description: hasHits ? 'Summary indicates one or more non-empty indicator lists.' : 'Summary shows no indicators found.',
        severity: hasHits ? 'low' : 'info',
        tags: ['shaihulu','threat-intel'],
        metadata: { summary_path: summaryPath },
      });
    } catch (e) {
      logger.warn({ e }, 'Failed to parse Shai-Hulud summary');
    }
  }

  cancel(scanId: string): void {
    this.clearTimers(scanId);
    this.appendLog(scanId, 'Scan canceled');
    this.broadcast(scanId, { type: 'done', message: 'canceled', timestamp: new Date().toISOString() });
  }

  private clearTimers(scanId: string): void {
    const timers = this.timers.get(scanId) || [];
    for (const t of timers) clearTimeout(t);
    this.timers.delete(scanId);
  }
}

export const scanRunner = new InMemoryScanRunner();

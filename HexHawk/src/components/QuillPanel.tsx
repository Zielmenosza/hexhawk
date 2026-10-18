import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { sanitizePluginFilename } from '../utils/tauriGuards';

function hasTauriRuntime(): boolean {
  return typeof window !== 'undefined' && typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

// ─── Types ────────────────────────────────────────────────────────────────────

export type UserPluginInfo = {
  filename: string;
  path: string;
  name: string;
  description: string;
  version: string;
  load_error: string | null;
};

// ─── PluginManager ────────────────────────────────────────────────────────────

interface Props {
  /** Called after install / uninstall so the parent can re-run plugins. */
  onPluginListChanged?: () => void;
}

export default function QuillPanel({ onPluginListChanged }: Props) {
  const [userPlugins, setUserPlugins] = useState<UserPluginInfo[]>([]);
  const [pluginDir, setPluginDir] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    loadPlugins();
  }, []);

  async function loadPlugins() {
    if (!hasTauriRuntime()) {
      setPluginDir('Browser mode (simulated plugin directory)');
      setUserPlugins([
        {
          filename: 'demo_rules.hexhawk-plugin.json',
          path: '/browser/simulated/demo_rules.hexhawk-plugin.json',
          name: 'DemoRules',
          description: 'Simulated advisory-only manifest plugin for browser testing',
          version: '1.0.0',
          load_error: null,
        },
      ]);
      setError(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const [dir, plugins] = await Promise.all([
        invoke<string>('get_plugin_directory'),
        invoke<UserPluginInfo[]>('list_user_plugins'),
      ]);
      setPluginDir(dir);
      setUserPlugins(plugins);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleInstall() {
    setError(null);
    setSuccessMsg(null);

    if (!hasTauriRuntime()) {
      setSuccessMsg('Browser mode: simulated plugin installation complete.');
      await loadPlugins();
      onPluginListChanged?.();
      return;
    }

    try {
      await open({
        title: 'Select HexHawk Advisory Plugin Manifest',
        filters: [
          { name: 'HexHawk Advisory Plugin Manifest', extensions: ['json'] },
        ],
        multiple: false,
      });
    } catch {
      return; // dialog cancelled
    }

    setInstalling(false);
    setError(
      'Phase 1 plugin safety gate: native plugin installation is disabled. ' +
      'Use manifest-only advisory plugins after the backend manifest runtime is wired.',
    );
  }

  async function handleUninstall(filename: string, displayName: string) {
    setError(null);
    setSuccessMsg(null);

    if (!hasTauriRuntime()) {
      setUserPlugins((prev) => prev.filter((p) => p.filename !== filename));
      setSuccessMsg(`Removed "${displayName}" (browser simulation).`);
      onPluginListChanged?.();
      return;
    }

    try {
      const safeFilename = sanitizePluginFilename(filename);
      await invoke('uninstall_plugin', { filename: safeFilename });
      setSuccessMsg(`Removed "${displayName}".`);
      await loadPlugins();
      onPluginListChanged?.();
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleOpenDir() {
    setError(null);
    if (!hasTauriRuntime()) {
      setSuccessMsg('Browser mode: plugin directory open is simulated.');
      return;
    }

    try {
      await invoke('open_plugin_directory');
    } catch (e) {
      setError(String(e));
    }
  }

  const loadedCount = userPlugins.filter(p => !p.load_error).length;
  const errorCount  = userPlugins.filter(p => !!p.load_error).length;

  return (
    <div className="plugin-manager">
      {/* Header row */}
      <div className="plugin-manager-header">
        <div className="plugin-manager-title">
          <span className="plugin-manager-icon">🪶</span>
          <h4>QUILL — User Plugins</h4>
          {userPlugins.length > 0 && (
            <span className="plugin-manager-count">
              {loadedCount} loaded{errorCount > 0 ? `, ${errorCount} failed` : ''}
            </span>
          )}
        </div>
        <div className="plugin-manager-actions">
          <button
            type="button"
            className="plugin-mgr-btn"
            onClick={handleOpenDir}
            title={pluginDir || 'Open plugin folder'}
          >
            📂 Open Folder
          </button>
          <button
            type="button"
            className="plugin-mgr-btn primary"
            onClick={handleInstall}
            disabled={installing}
          >
            {installing ? '⏳ Installing…' : '+ Install Plugin'}
          </button>
          <button
            type="button"
            className="plugin-mgr-btn"
            onClick={loadPlugins}
            disabled={loading}
          >
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* Plugin directory path */}
      {pluginDir && (
        <div className="plugin-dir-path" title={pluginDir}>
          {pluginDir}
        </div>
      )}

      {/* Feedback banners */}
      {error && (
        <div className="plugin-banner error">
          ⚠ {error}
          <button type="button" onClick={() => setError(null)}>×</button>
        </div>
      )}
      {successMsg && (
        <div className="plugin-banner success">
          ✓ {successMsg}
          <button type="button" onClick={() => setSuccessMsg(null)}>×</button>
        </div>
      )}

      {/* Plugin list */}
      {loading ? (
        <p className="plugin-loading">Loading…</p>
      ) : userPlugins.length === 0 ? (
        <div className="plugin-empty">
          <p>No advisory plugins installed.</p>
          <div className="plugin-sdk-hint">
            <strong>Phase 1 safe plugin contract</strong>
            <ol>
              <li>
                Create a <code>hexhawk.plugin_manifest.v1</code> JSON manifest with explicit permissions.
              </li>
              <li>
                Allowed Phase 1 permissions are read-only evidence access plus advisory observations/report sections.
              </li>
              <li>
                Native <code>.dll</code> / <code>.so</code> / <code>.dylib</code> plugins remain disabled until signed/trusted bundle review is implemented.
              </li>
            </ol>
            <p>Plugin output is advisory only and cannot mutate GYRE verdict authority.</p>
          </div>
        </div>
      ) : (
        <div className="plugin-user-list">
          {userPlugins.map(p => (
            <div
              key={p.filename}
              className={`plugin-user-card ${p.load_error ? 'load-error' : 'loaded'}`}
            >
              <div className="plugin-user-card-header">
                <div className="plugin-user-name">
                  <strong>{p.name || p.filename}</strong>
                  {p.version && (
                    <span className="plugin-user-version">v{p.version}</span>
                  )}
                </div>
                <span className={`plugin-load-badge ${p.load_error ? 'error' : 'ok'}`}>
                  {p.load_error ? '⚠ Load failed' : '✓ Loaded'}
                </span>
              </div>

              {p.description && (
                <div className="plugin-user-desc">{p.description}</div>
              )}

              {p.load_error && (
                <pre className="plugin-load-error-msg">{p.load_error}</pre>
              )}

              <div className="plugin-user-footer">
                <span className="plugin-user-filename" title={p.path}>
                  {p.filename}
                </span>
                <button
                  type="button"
                  className="plugin-uninstall-btn"
                  onClick={() => handleUninstall(p.filename, p.name || p.filename)}
                  title="Remove this plugin"
                >
                  Uninstall
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { sanitizeBridgePath, sanitizePluginFilename } from '../utils/tauriGuards';

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
          filename: 'demo_rules.dll',
          path: '/browser/simulated/demo_rules.dll',
          name: 'DemoRules',
          description: 'Simulated QUILL plugin for browser-only testing',
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

    let selected: string | string[] | null;
    try {
      selected = await open({
        title: 'Select HexHawk Plugin',
        filters: [
          { name: 'HexHawk Plugin', extensions: ['dll', 'so', 'dylib'] },
        ],
        multiple: false,
      });
    } catch {
      return; // dialog cancelled
    }
    if (!selected || Array.isArray(selected)) return;

    setInstalling(true);
    try {
      const safeSrcPath = sanitizeBridgePath(selected, 'plugin path');
      const info = await invoke<UserPluginInfo>('install_plugin', { srcPath: safeSrcPath });
      setSuccessMsg(`Installed "${info.name}" successfully.`);
      await loadPlugins();
      onPluginListChanged?.();
    } catch (e) {
      setError(String(e));
    } finally {
      setInstalling(false);
    }
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
          <p>No QUILL plugins installed.</p>
          <div className="plugin-sdk-hint">
            <strong>How to create a QUILL plugin</strong>
            <ol>
              <li>
                Create a new Rust crate with <code>crate-type = ["cdylib"]</code> and add
                <code>plugin_api = &#123; path = "../plugin-api" &#125;</code> as a dependency.
              </li>
              <li>
                Export a <code>#[no_mangle] pub extern "C" fn hexhawk_plugin_entry() -&gt; *const PluginEntry</code> symbol.
              </li>
              <li>
                Run <code>cargo build --release</code> and install the resulting
                <code>.dll</code> / <code>.so</code> / <code>.dylib</code> here.
              </li>
            </ol>
            <p>See <code>plugins/byte_counter/</code> in the repo for a complete example.</p>
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

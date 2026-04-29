/**
 * SettingsPanel.tsx — TALON LLM Decompilation Pass Settings
 *
 * Provides three controls:
 *   - Toggle:     Enable LLM decompilation pass
 *   - Text field: LLM endpoint URL
 *   - Text field: Model name
 */

import React from 'react';
import type { LLMPassConfig } from '../utils/talonLLMPass';
import { DEFAULT_LLM_CONFIG } from '../utils/talonLLMPass';

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface LLMSettings {
  enabled:                  boolean;
  provider:                 'open_ai' | 'anthropic' | 'ollama';
  action:                   'signal_explainer' | 'aerie_mode' | 'talon_narrate' | 'crest_narration' | 'binary_diff_insight';
  providerEnabled:          Record<'open_ai' | 'anthropic' | 'ollama', boolean>;
  featureEnabled:           Record<'signal_explainer' | 'aerie_mode' | 'talon_narrate' | 'crest_narration' | 'binary_diff_insight', boolean>;
  privacyDisclosureAccepted:boolean;
  sessionTokenCap:          number;
  endpointUrl:              string;
  modelName:                string;
  apiKey:                   string;
  keyAlias:                 string;
  useKeychain:              boolean;
  allowRemoteEndpoints:     boolean;
  allowAgentTools:          boolean;
  tokenBudget:              number;
}

export const DEFAULT_LLM_SETTINGS: LLMSettings = {
  enabled:                 false,
  provider:                'ollama',
  action:                  'talon_narrate',
  providerEnabled: {
    open_ai:   true,
    anthropic: true,
    ollama:    true,
  },
  featureEnabled: {
    signal_explainer:    false,
    aerie_mode:          false,
    talon_narrate:       true,
    crest_narration:     false,
    binary_diff_insight: false,
  },
  privacyDisclosureAccepted: false,
  sessionTokenCap:         20_000,
  endpointUrl:             DEFAULT_LLM_CONFIG.endpointUrl,
  modelName:               DEFAULT_LLM_CONFIG.modelName,
  apiKey:                  '',
  keyAlias:                DEFAULT_LLM_CONFIG.keyAlias,
  useKeychain:             true,
  allowRemoteEndpoints:    false,
  allowAgentTools:         false,
  tokenBudget:             DEFAULT_LLM_CONFIG.tokenBudget,
};

interface Props {
  settings:        LLMSettings;
  onChange:        (next: LLMSettings) => void;
  onClose:         () => void;
  hasStoredApiKey: Record<'open_ai' | 'anthropic' | 'ollama', boolean>;
  onSaveApiKey:    () => void;
  onClearApiKey:   () => void;
  onTestApiKey:    () => void;
  llmError?:       string | null;
}

// ─── Component ─────────────────────────────────────────────────────────────────

export default function SettingsPanel({
  settings,
  onChange,
  onClose,
  hasStoredApiKey,
  onSaveApiKey,
  onClearApiKey,
  onTestApiKey,
  llmError,
}: Props) {
  function set<K extends keyof LLMSettings>(key: K, value: LLMSettings[K]) {
    onChange({ ...settings, [key]: value });
  }

  function setProviderEnabled(provider: 'open_ai' | 'anthropic' | 'ollama', enabled: boolean) {
    onChange({
      ...settings,
      providerEnabled: {
        ...settings.providerEnabled,
        [provider]: enabled,
      },
    });
  }

  function setFeatureEnabled(
    feature: 'signal_explainer' | 'aerie_mode' | 'talon_narrate' | 'crest_narration' | 'binary_diff_insight',
    enabled: boolean,
  ) {
    onChange({
      ...settings,
      featureEnabled: {
        ...settings.featureEnabled,
        [feature]: enabled,
      },
    });
  }

  function providerDefaults(provider: LLMSettings['provider']): { endpointUrl: string; modelName: string } {
    if (provider === 'open_ai') {
      return {
        endpointUrl: 'https://api.openai.com/v1/chat/completions',
        modelName: 'gpt-4o-mini',
      };
    }
    if (provider === 'anthropic') {
      return {
        endpointUrl: 'https://api.anthropic.com/v1/messages',
        modelName: 'claude-3-5-sonnet-latest',
      };
    }
    return {
      endpointUrl: 'http://localhost:11434/api/chat',
      modelName: 'codellama:7b',
    };
  }

  const selectedProviderStoredKey = hasStoredApiKey[settings.provider];
  const providerNeedsKey = settings.provider !== 'ollama';

  return (
    <div className="tln-settings-panel" role="dialog" aria-label="TALON LLM settings">
      <div className="tln-settings-header">
        <span className="tln-settings-title">LLM Decompilation Pass</span>
        <button
          type="button"
          className="tln-settings-close"
          onClick={onClose}
          aria-label="Close settings"
        >
          ✕
        </button>
      </div>

      <div className="tln-settings-body">
        {/* Toggle */}
        <label className="tln-settings-row tln-settings-toggle-row">
          <span className="tln-settings-label">Enable LLM decompilation pass</span>
          <span className="tln-toggle-wrap">
            <input
              type="checkbox"
              className="tln-toggle-input"
              checked={settings.enabled}
              onChange={e => set('enabled', e.target.checked)}
            />
            <span className="tln-toggle-track" aria-hidden="true" />
          </span>
        </label>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Provider</span>
          <select
            className="tln-settings-input"
            value={settings.provider}
            disabled={!settings.enabled}
            onChange={e => {
              const provider = e.target.value as LLMSettings['provider'];
              const defaults = providerDefaults(provider);
              onChange({
                ...settings,
                provider,
                endpointUrl: defaults.endpointUrl,
                modelName: defaults.modelName,
              });
            }}
          >
            <option value="ollama">Local Ollama</option>
            <option value="open_ai">OpenAI</option>
            <option value="anthropic">Anthropic</option>
          </select>
        </div>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Active AI action</span>
          <select
            className="tln-settings-input"
            value={settings.action}
            disabled={!settings.enabled}
            onChange={e => set('action', e.target.value as LLMSettings['action'])}
          >
            <option value="talon_narrate">TALON narrate</option>
            <option value="signal_explainer">Signal explainer</option>
            <option value="aerie_mode">AERIE mode</option>
            <option value="crest_narration">CREST narration</option>
            <option value="binary_diff_insight">Binary diff insight</option>
          </select>
          <span className="tln-settings-hint">Only enabled features can be executed.</span>
        </div>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Feature toggles (explicit)</span>
          <div className="tln-settings-toggle-grid">
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">TALON narrate</span>
              <input type="checkbox" checked={settings.featureEnabled.talon_narrate} disabled={!settings.enabled} onChange={e => setFeatureEnabled('talon_narrate', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">Signal explainer</span>
              <input type="checkbox" checked={settings.featureEnabled.signal_explainer} disabled={!settings.enabled} onChange={e => setFeatureEnabled('signal_explainer', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">AERIE mode</span>
              <input type="checkbox" checked={settings.featureEnabled.aerie_mode} disabled={!settings.enabled} onChange={e => setFeatureEnabled('aerie_mode', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">CREST narration</span>
              <input type="checkbox" checked={settings.featureEnabled.crest_narration} disabled={!settings.enabled} onChange={e => setFeatureEnabled('crest_narration', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">Binary diff insight</span>
              <input type="checkbox" checked={settings.featureEnabled.binary_diff_insight} disabled={!settings.enabled} onChange={e => setFeatureEnabled('binary_diff_insight', e.target.checked)} />
            </label>
          </div>
        </div>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Provider availability</span>
          <div className="tln-settings-toggle-grid">
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">OpenAI enabled</span>
              <input type="checkbox" checked={settings.providerEnabled.open_ai} disabled={!settings.enabled} onChange={e => setProviderEnabled('open_ai', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">Anthropic enabled</span>
              <input type="checkbox" checked={settings.providerEnabled.anthropic} disabled={!settings.enabled} onChange={e => setProviderEnabled('anthropic', e.target.checked)} />
            </label>
            <label className="tln-settings-toggle-row tln-settings-toggle-compact">
              <span className="tln-settings-hint">Local Ollama enabled</span>
              <input type="checkbox" checked={settings.providerEnabled.ollama} disabled={!settings.enabled} onChange={e => setProviderEnabled('ollama', e.target.checked)} />
            </label>
          </div>
        </div>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Privacy disclosure</span>
          <div className="tln-settings-note" style={{ margin: 0 }}>
            AI requests may include selected decompiled content and intent tags. No background model calls are made.
            You must explicitly run and confirm each request.
          </div>
          <label className="tln-settings-toggle-row tln-settings-toggle-compact" style={{ marginTop: 8 }}>
            <span className="tln-settings-hint">I understand and accept this disclosure</span>
            <input type="checkbox" checked={settings.privacyDisclosureAccepted} disabled={!settings.enabled} onChange={e => set('privacyDisclosureAccepted', e.target.checked)} />
          </label>
        </div>

        <div className="tln-settings-row">
          <span className="tln-settings-label">Session token cap</span>
          <input
            type="number"
            min={512}
            max={200000}
            className="tln-settings-input"
            value={settings.sessionTokenCap}
            disabled={!settings.enabled}
            onChange={e => set('sessionTokenCap', Math.max(512, Number(e.target.value) || 20_000))}
          />
        </div>

        <div className="tln-settings-row" style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: 10 }}>
          <span className="tln-settings-label">Secret storage (Stronghold)</span>
          <span className="tln-settings-hint">Provider keys are stored securely and separate from ordinary settings.</span>
        </div>

        {/* Endpoint URL */}
        <label className="tln-settings-row">
          <span className="tln-settings-label">LLM endpoint URL</span>
          <input
            type="url"
            className="tln-settings-input"
            value={settings.endpointUrl}
            placeholder={DEFAULT_LLM_CONFIG.endpointUrl}
            disabled={!settings.enabled}
            onChange={e => set('endpointUrl', e.target.value)}
            spellCheck={false}
          />
        </label>

        {/* Model name */}
        <label className="tln-settings-row">
          <span className="tln-settings-label">Model name</span>
          <input
            type="text"
            className="tln-settings-input"
            value={settings.modelName}
            placeholder={DEFAULT_LLM_CONFIG.modelName}
            disabled={!settings.enabled}
            onChange={e => set('modelName', e.target.value)}
            spellCheck={false}
          />
        </label>

        {/* Optional API key (for OpenAI-compatible endpoints) */}
        <label className="tln-settings-row">
          <span className="tln-settings-label">
            API key{' '}
            <span className="tln-settings-hint">{providerNeedsKey ? '(required for remote provider)' : '(optional for local Ollama)'}</span>
          </span>
          <input
            type="password"
            className="tln-settings-input"
            value={settings.apiKey}
            placeholder="sk-…"
            disabled={!settings.enabled}
            autoComplete="off"
            onChange={e => set('apiKey', e.target.value)}
          />
        </label>

        <label className="tln-settings-row">
          <span className="tln-settings-label">Key alias</span>
          <input
            type="text"
            className="tln-settings-input"
            value={settings.keyAlias}
            placeholder={DEFAULT_LLM_CONFIG.keyAlias}
            disabled={!settings.enabled}
            onChange={e => set('keyAlias', e.target.value)}
            spellCheck={false}
          />
        </label>

        <label className="tln-settings-row tln-settings-toggle-row">
          <span className="tln-settings-label">Use keychain stored key</span>
          <span className="tln-toggle-wrap">
            <input
              type="checkbox"
              className="tln-toggle-input"
              checked={settings.useKeychain}
              disabled={!settings.enabled}
              onChange={e => set('useKeychain', e.target.checked)}
            />
            <span className="tln-toggle-track" aria-hidden="true" />
          </span>
        </label>

        <div className="tln-settings-row tln-settings-actions">
          <button type="button" className="tln-btn" disabled={!settings.enabled || (!settings.apiKey && !selectedProviderStoredKey)} onClick={onSaveApiKey}>
            {selectedProviderStoredKey ? 'Update key securely' : 'Add key securely'}
          </button>
          <button type="button" className="tln-btn" disabled={!settings.enabled || !selectedProviderStoredKey} onClick={onClearApiKey}>
            Remove stored key
          </button>
          <button type="button" className="tln-btn" disabled={!settings.enabled} onClick={onTestApiKey}>
            Test provider
          </button>
          <span className="tln-settings-hint">Stored key ({settings.provider}): {selectedProviderStoredKey ? 'yes' : 'no'}</span>
        </div>

        <label className="tln-settings-row tln-settings-toggle-row">
          <span className="tln-settings-label">Allow remote endpoint (non-localhost)</span>
          <span className="tln-toggle-wrap">
            <input
              type="checkbox"
              className="tln-toggle-input"
              checked={settings.allowRemoteEndpoints}
              disabled={!settings.enabled}
              onChange={e => set('allowRemoteEndpoints', e.target.checked)}
            />
            <span className="tln-toggle-track" aria-hidden="true" />
          </span>
        </label>

        <label className="tln-settings-row tln-settings-toggle-row">
          <span className="tln-settings-label">Allow agent/tool directives in LLM output</span>
          <span className="tln-toggle-wrap">
            <input
              type="checkbox"
              className="tln-toggle-input"
              checked={settings.allowAgentTools}
              disabled={!settings.enabled}
              onChange={e => set('allowAgentTools', e.target.checked)}
            />
            <span className="tln-toggle-track" aria-hidden="true" />
          </span>
        </label>

        <label className="tln-settings-row">
          <span className="tln-settings-label">Token budget</span>
          <input
            type="number"
            min={256}
            max={16384}
            className="tln-settings-input"
            value={settings.tokenBudget}
            disabled={!settings.enabled}
            onChange={e => set('tokenBudget', Number(e.target.value) || DEFAULT_LLM_CONFIG.tokenBudget)}
          />
        </label>

        {settings.enabled && (
          <p className="tln-settings-note">
            LLM pass is manual-only. Every call requires explicit confirmation.
            Output is advisory and falls back to TALON output on any failure.
            {llmError ? ` Last status: ${llmError}` : ''}
          </p>
        )}
      </div>
    </div>
  );
}

/** Convert LLMSettings into the LLMPassConfig shape required by runLLMPass. */
export function settingsToConfig(s: LLMSettings): LLMPassConfig {
  const providerDefaults: Record<LLMSettings['provider'], { endpoint: string; model: string }> = {
    ollama: {
      endpoint: 'http://localhost:11434/api/chat',
      model: 'codellama:7b',
    },
    open_ai: {
      endpoint: 'https://api.openai.com/v1/chat/completions',
      model: 'gpt-4o-mini',
    },
    anthropic: {
      endpoint: 'https://api.anthropic.com/v1/messages',
      model: 'claude-3-5-sonnet-latest',
    },
  };

  const defaults = providerDefaults[s.provider];
  return {
    provider:             s.provider,
    action:               s.action,
    providerEnabled:      s.providerEnabled,
    featureEnabled:       s.featureEnabled,
    privacyDisclosureAccepted: s.privacyDisclosureAccepted,
    sessionTokenCap:      Math.max(512, s.sessionTokenCap || 20_000),
    sessionTokensUsed:    0,
    endpointUrl:          s.endpointUrl || defaults.endpoint,
    modelName:            s.modelName || defaults.model,
    apiKey:               s.apiKey || undefined,
    keyAlias:             s.keyAlias || DEFAULT_LLM_CONFIG.keyAlias,
    useKeychain:          s.useKeychain,
    approvalGranted:      false,
    allowRemoteEndpoints: s.allowRemoteEndpoints,
    allowAgentTools:      s.allowAgentTools,
    tokenBudget:          Math.max(256, Math.min(16384, s.tokenBudget || DEFAULT_LLM_CONFIG.tokenBudget)),
    maxPromptChars:       DEFAULT_LLM_CONFIG.maxPromptChars,
    timeoutMs:            DEFAULT_LLM_CONFIG.timeoutMs,
    maxPromptLines:       DEFAULT_LLM_CONFIG.maxPromptLines,
  };
}

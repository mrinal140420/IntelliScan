import React from 'react';

interface SettingsPageProps {
  audioEnabled: boolean;
  onAudioToggle: () => void;
  onClearHistory: () => void;
}

export default function SettingsPage({ audioEnabled, onAudioToggle, onClearHistory }: SettingsPageProps) {
  return (
    <div className="page-container settings-page">
      <div className="card">
        <h2 className="card-title">Settings</h2>

        {/* Audio Settings */}
        <div className="settings-group">
          <h3 className="settings-group-title">Audio & Feedback</h3>

          <div className="settings-row">
            <div className="settings-label-section">
              <p className="settings-label">Audio Feedback</p>
              <p className="settings-description">Play sound effects for interface interactions and scan events</p>
            </div>
            <button
              onClick={onAudioToggle}
              className={`btn btn-sm ${audioEnabled ? 'btn-primary' : 'btn-secondary'}`}
            >
              {audioEnabled ? 'ON' : 'OFF'}
            </button>
          </div>

          {audioEnabled && (
            <div className="alert alert-info">
              <p className="alert-title">Audio is enabled. You will hear:</p>
              <ul className="alert-list">
                <li>Deep tone (150Hz) when a scan starts</li>
                <li>Sharp sound (800Hz) for critical findings</li>
                <li>Rising tone sequence when scan completes</li>
                <li>Subtle feedback on button interactions</li>
              </ul>
            </div>
          )}
        </div>

        {/* Detector Settings */}
        <div className="settings-group">
          <h3 className="settings-group-title">Detection Engine</h3>

          <div className="detector-grid">
            {[
              {
                name: 'Hybrid Detection',
                description: 'Combines regex patterns, AST analysis, and TF-IDF scoring for lightweight and accurate scanning.',
              },
              {
                name: 'Regex Rule Engine',
                description: 'Curated vulnerability patterns that detect real-world insecure coding practices.',
              },
              {
                name: 'AST Static Analysis',
                description: 'Inspects code structure and unsafe function calls to reduce false positives.',
              },
              {
                name: 'Risk Scoring',
                description: 'Ranks findings by severity and context so critical issues stand out in reports.',
              },
            ].map((detector) => (
              <div key={detector.name} className="detector-card">
                <p className="detector-name">{detector.name}</p>
                <p className="detector-description">{detector.description}</p>
                <span className="detector-status">Enabled</span>
              </div>
            ))}
          </div>

          <div className="settings-row settings-clear-history">
            <div className="settings-label-section">
              <p className="settings-label">Saved History</p>
              <p className="settings-description">
                Clear history when you want to remove stored scan metadata and findings.
              </p>
            </div>
            <button
              type="button"
              onClick={onClearHistory}
              className="btn btn-secondary btn-sm"
            >
              Clear Saved History
            </button>
          </div>
        </div>

        {/* About */}
        <div className="settings-group">
          <h3 className="settings-group-title">About</h3>

          <div className="settings-info-box">
            <p className="info-title">SecureHub IntelliScan</p>
            <p className="info-subtitle">Enterprise Security Scanner</p>
            <p className="info-text">
              Advanced code vulnerability detection using a hybrid engine of pattern rules and AST-based analysis. Detects SQL injection, command injection, hardcoded secrets, and other critical vulnerabilities.
            </p>
            <p className="info-copyright">© 2026 SecureHub. All rights reserved.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

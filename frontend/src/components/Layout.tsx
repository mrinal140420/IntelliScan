import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import AudioVisualizer from './AudioVisualizer';
import { LOGO_URL } from '../utils/constants';

interface LayoutProps {
  children: React.ReactNode;
  audioEnabled: boolean;
  onAudioToggle: () => void;
  isPlayingAudio: boolean;
}

export default function Layout({ children, audioEnabled, onAudioToggle, isPlayingAudio }: LayoutProps) {
  const location = useLocation();

  return (
    <div className="layout">
      {/* HEADER */}
      <header className="layout-header">
        <div className="layout-header-logo">
          <img
            src={LOGO_URL}
            alt="SecureHub Logo"
            className="layout-logo-image"
          />
          <div>
            <h1 className="layout-title">SecureHub IntelliScan</h1>
            <p className="layout-subtitle">AI Code Security Analyzer</p>
            <p className="layout-tagline">Scan Smart. Code Secure.</p>
          </div>
        </div>

      </header>

      {/* NAVIGATION */}
      <nav className="layout-nav">
        {[
          { path: '/', label: 'Dashboard' },
          { path: '/scan', label: 'New Scan' },
          { path: '/history', label: 'History' },
          { path: '/settings', label: 'Settings' },
        ].map((tab) => (
          <Link
            key={tab.path}
            to={tab.path}
            className={`layout-nav-link ${location.pathname === tab.path ? 'active' : ''}`}
          >
            {tab.label}
          </Link>
        ))}
      </nav>

      {/* AUDIO VISUALIZER */}
      <div className="layout-audio">
        <AudioVisualizer isPlaying={isPlayingAudio} severity="INFO" />
        <button
          onClick={onAudioToggle}
          className={`layout-audio-toggle ${audioEnabled ? 'active' : ''}`}
          title={audioEnabled ? 'Audio On' : 'Audio Off'}
        >
          {audioEnabled ? 'ON' : 'OFF'}
        </button>
      </div>

      {/* MAIN CONTENT */}
      <main className="layout-main">
        {children}
      </main>

      {/* FOOTER */}
      <footer className="layout-footer">
        <p className="info-copyright">© 2026 SecureHub. All rights reserved.</p>
      </footer>
    </div>
  );
}
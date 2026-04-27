import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ScanPage from './pages/ScanPage';
import HistoryPage from './pages/HistoryPage';
import SettingsPage from './pages/SettingsPage';
import Layout from './components/Layout';
import { initializeAudioContext, setAudioEnabled } from './utils/audio';

export default function App() {
  const [audioEnabled, setAudioEnabledState] = useState(() => {
    try {
      const stored = localStorage.getItem('securehub_audio_enabled');
      return stored !== null ? stored === 'true' : true;
    } catch {
      return true;
    }
  });
  const [isPlayingAudio, setIsPlayingAudio] = useState(false);
  const [scans, setScans] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('securehub_scans') ?? '[]');
    } catch {
      return [];
    }
  });
  const [findings, setFindings] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('securehub_findings') ?? '[]');
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      initializeAudioContext();
    } catch (error) {
      console.warn('Audio context initialization failed:', error);
    }
  }, []);

  useEffect(() => {
    const loadRecentScans = async () => {
      try {
        const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const response = await fetch(`${apiUrl}/api/v1/scans/recent?limit=10`);
        if (!response.ok) {
          throw new Error(`Failed to fetch recent scans: ${response.statusText}`);
        }

        const data = await response.json();
        const fetchedScans = (data.scans || []).map((scan: any) => ({
          id: scan.scan_id,
          projectName: scan.project_name,
          status: scan.status,
          createdAt: scan.created_at,
          filesAnalyzed: scan.files_analyzed,
          securityScore: scan.security_score,
          totalFindings: scan.total_findings,
          severityBreakdown: scan.severity_breakdown || {},
          scanType: scan.scan_type,
        }));

        if (fetchedScans.length > 0) {
          setScans(fetchedScans);
        }
      } catch (error) {
        console.warn('Unable to load recent scans from database:', error);
      }
    };

    loadRecentScans();
  }, []);

  useEffect(() => {
    const loadFindingsForLatestScan = async () => {
      try {
        if (findings.length > 0 || scans.length === 0) {
          return;
        }

        const latestScanId = scans[0]?.id;
        if (!latestScanId) {
          return;
        }

        const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const response = await fetch(`${apiUrl}/api/v1/scans/${latestScanId}`);
        if (!response.ok) {
          console.warn(`Failed to load scan details for findings: ${response.statusText}`);
          return;
        }

        const scanDetail = await response.json();
        const recoveredFindings = (scanDetail.findings || []).map((finding: any, idx: number) => ({
          id: `${scanDetail.scan_id}-${idx + 1}`,
          vulnerability_type: finding.type || finding.vulnerability_type || 'Unknown',
          severity: (finding.severity || 'info').toString().toUpperCase(),
          cvss_score: Number(finding.cve_score ?? finding.cvss_score ?? 0),
          file_path: finding.filename || finding.file_path || 'Unknown',
          line_number: finding.line_number ?? 0,
          code_snippet: finding.code_snippet || finding.description || '',
        }));

        if (recoveredFindings.length > 0) {
          setFindings(recoveredFindings);
        }
      } catch (error) {
        console.warn('Unable to restore findings from latest scan:', error);
      }
    };

    loadFindingsForLatestScan();
  }, [scans, findings.length]);

  useEffect(() => {
    localStorage.setItem('securehub_scans', JSON.stringify(scans));
  }, [scans]);

  useEffect(() => {
    localStorage.setItem('securehub_findings', JSON.stringify(findings));
  }, [findings]);

  useEffect(() => {
    localStorage.setItem('securehub_audio_enabled', String(audioEnabled));
  }, [audioEnabled]);

  const handleAudioToggle = () => {
    const newState = !audioEnabled;
    setAudioEnabledState(newState);
    setAudioEnabled(newState);
  };

  const handleClearHistory = () => {
    setScans([]);
    setFindings([]);
    localStorage.removeItem('securehub_scans');
    localStorage.removeItem('securehub_findings');
  };

  const handleNewScan = (scanData: any) => {
    const newScan = {
      id: scanData.scan_id,
      projectName: scanData.project_name,
      scanType: scanData.scan_type,
      status: 'COMPLETED',
      createdAt: scanData.timestamp,
      filesAnalyzed: scanData.files_analyzed,
      securityScore: scanData.security_score,
      totalFindings: scanData.total_findings,
      severityBreakdown: scanData.severity_breakdown,
    };
    setScans((prevScans) => [newScan, ...prevScans]);

    const actualFindings = (scanData.findings || []).map((finding: any, idx: number) => ({
      id: `${scanData.scan_id}-${idx + 1}`,
      vulnerability_type: finding.type,
      severity: finding.severity.toUpperCase(),
      cvss_score: finding.cve_score,
      file_path: finding.filename,
      line_number: finding.line_number || 0,
      code_snippet: finding.code_snippet || finding.description || '',
      confidence: finding.confidence,
      source: finding.source,
    }));
    setFindings(actualFindings);
  };

  return (
    <BrowserRouter>
      <Layout audioEnabled={audioEnabled} onAudioToggle={handleAudioToggle} isPlayingAudio={isPlayingAudio}>
        <Routes>
          <Route path="/" element={<Dashboard scans={scans} findings={findings} />} />
          <Route path="/scan" element={<ScanPage onNewScan={handleNewScan} onAudioPlay={setIsPlayingAudio} />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/settings" element={<SettingsPage audioEnabled={audioEnabled} onAudioToggle={handleAudioToggle} onClearHistory={handleClearHistory} />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

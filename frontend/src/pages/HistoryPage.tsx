import React, { useEffect, useState } from 'react';

interface Scan {
  scan_id: string;
  project_name: string;
  scan_type: string;
  status: string;
  created_at: string;
  files_analyzed: number;
  security_score: number;
  total_findings: number;
  severity_breakdown: Record<string, number>;
}

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const response = await fetch(`${apiUrl}/api/v1/scans/recent?limit=100`);
        
        if (!response.ok) {
          throw new Error(`Failed to fetch history: ${response.statusText}`);
        }

        const data = await response.json();
        setScans(data.scans || []);
        setError('');
      } catch (err) {
        console.error('Failed to fetch scan history:', err);
        setError(err instanceof Error ? err.message : 'Failed to fetch history');
        setScans([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, []);

  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  const openReport = (scanId: string) => {
    window.open(`${apiUrl}/api/v1/scans/${scanId}/report?format=html`, '_blank');
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">Scan History</h2>
        <p className="page-subtitle">View all your past scans and their findings from the security database.</p>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {loading ? (
        <div className="loading-container">
          <p className="loading-text">Loading history...</p>
          <div className="spinner" />
        </div>
      ) : scans.length === 0 ? (
        <div className="card empty-state">
          <p className="empty-state-text">No scan history found. Run a new scan to get started.</p>
        </div>
      ) : (
        <div className="history-list">
          {scans.map((scan, idx) => (
            <div key={scan.scan_id || idx} className="history-item">
              {/* Project Info */}
              <div className="history-item-info">
                <h3 className="history-item-name">{scan.project_name}</h3>
                <p className="history-item-meta">{new Date(scan.created_at).toLocaleString()}</p>
                <div className="history-item-actions">
                  <span className="scan-type-pill">{scan.scan_type}</span>
                  <button className="btn btn-secondary btn-sm" onClick={() => openReport(scan.scan_id)}>
                    View Report
                  </button>
                </div>
              </div>

              {/* Files Analyzed */}
              <div className="history-item-stat">
                <div className="stat-label">Files</div>
                <div className="stat-value">{scan.files_analyzed}</div>
              </div>

              {/* Total Findings */}
              <div className="history-item-stat">
                <div className="stat-label">Issues</div>
                <div className="stat-value" style={{ color: scan.total_findings > 0 ? 'var(--severity-high)' : 'var(--severity-safe)' }}>
                  {scan.total_findings}
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="history-item-stat">
                <div className="stat-label">Breakdown</div>
                <div className="severity-breakdown">
                  {scan.severity_breakdown && scan.severity_breakdown.critical > 0 && (
                    <span className="severity-badge severity-critical">C:{scan.severity_breakdown.critical}</span>
                  )}
                  {scan.severity_breakdown && scan.severity_breakdown.high > 0 && (
                    <span className="severity-badge severity-high">H:{scan.severity_breakdown.high}</span>
                  )}
                  {scan.severity_breakdown && scan.severity_breakdown.medium > 0 && (
                    <span className="severity-badge severity-medium">M:{scan.severity_breakdown.medium}</span>
                  )}
                </div>
              </div>

              {/* Security Score */}
              <div className="history-item-stat">
                <div className="stat-label">Score</div>
                <div className="stat-value stat-score">{scan.security_score.toFixed(0)}%</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

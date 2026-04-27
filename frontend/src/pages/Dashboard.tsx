import React from 'react';

interface Scan {
  id: string;
  projectName: string;
  status: string;
  createdAt: string;
  filesAnalyzed?: number;
  securityScore?: number;
  totalFindings?: number;
  scanType?: string;
  severityBreakdown?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
}

interface Finding {
  id: string | number;
  vulnerability_type: string;
  severity: string;
  cvss_score: number;
  file_path: string;
}

interface DashboardProps {
  scans: Scan[];
  findings: Finding[];
}

export default function Dashboard({ scans, findings }: DashboardProps) {
  const criticalCount = scans.reduce((count, scan) => count + (scan.severityBreakdown?.critical || 0), 0);
  const highCount = scans.reduce((count, scan) => count + (scan.severityBreakdown?.high || 0), 0);
  const totalScans = scans.length;
  const securityScore =
    totalScans > 0
      ? Math.round(scans.reduce((sum, scan) => sum + (scan.securityScore || 0), 0) / totalScans)
      : 100;

  return (
    <div className="dashboard-section">
      <div className="metrics-grid">
        {[
          { label: 'Total Scans', value: totalScans, unit: '', accentColor: 'info' },
          { label: 'Critical Issues', value: criticalCount, unit: '', accentColor: 'critical' },
          { label: 'High Priority', value: highCount, unit: '', accentColor: 'high' },
          { label: 'Security Score', value: securityScore, unit: '%', accentColor: 'safe' },
        ].map((metric, idx) => (
          <div key={idx} className={`metric-card metric-card-${metric.accentColor}`}>
            <div className="metric-card-label">{metric.label}</div>
            <div className="metric-card-value">
              {metric.value}
              {metric.unit && <span className="metric-card-unit">{metric.unit}</span>}
            </div>
          </div>
        ))}
      </div>

      <div className="dashboard-card">
        <h2 className="dashboard-card-title">Scan Summary</h2>
        <p className="dashboard-card-description">
          Full scan history is available in <strong>History</strong>. Dashboard shows the latest
          snapshot and top vulnerability trends.
        </p>
        {scans.length > 0 ? (
          <div className="summary-grid">
            <div className="summary-item">
              <div className="summary-item-label">Latest Scan</div>
              <div className="summary-item-value">{scans[0].projectName}</div>
              <div className="summary-item-meta">{new Date(scans[0].createdAt).toLocaleString()}</div>
            </div>
            <div className="summary-item">
              <div className="summary-item-label">Issues</div>
              <div className="summary-item-value">{scans[0].totalFindings ?? 0}</div>
            </div>
            <div className="summary-item">
              <div className="summary-item-label">Score</div>
              <div className="summary-item-value summary-score">
                {scans[0].securityScore?.toFixed(0) ?? '0'}%
              </div>
            </div>
          </div>
        ) : (
          <p className="no-data-message">No scans yet. Run a scan to see metrics and history.</p>
        )}
      </div>

      {findings.length > 0 && (
        <div className="dashboard-card">
          <h2 className="dashboard-card-title">Top Vulnerabilities</h2>
          <div className="vulnerabilities-list">
            {findings.slice(0, 5).map((finding) => (
              <div
                key={finding.id}
                className={`vulnerability-item vulnerability-${finding.severity.toLowerCase()}`}
              >
                <div className="vulnerability-info">
                  <p className="vulnerability-type">{finding.vulnerability_type}</p>
                  <p className="vulnerability-path">{finding.file_path}</p>
                </div>
                <div className="vulnerability-meta">
                  <span className="vulnerability-cvss">CVSS: {Number(finding.cvss_score).toFixed(1)}</span>
                  <span className={`badge badge-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

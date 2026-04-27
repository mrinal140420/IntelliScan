import React, { useState, useRef, useEffect } from 'react';
import { playScanchInitiatedSound, playButtonClickSound, playFindingSound, playScanCompleteSound } from '../utils/audio';
import { LOGO_URL } from '../utils/constants';

interface ScanPageProps {
  onNewScan: (scanData: any) => void;
  onAudioPlay?: (playing: boolean) => void;
}

interface ScanResult {
  scan_id: string;
  project_name: string;
  status: string;
  files_analyzed: number;
  total_findings: number;
  security_score: number;
  severity_breakdown: Record<string, number>;
  findings: Array<any>;
  timestamp: string;
  duration_seconds: number;
}

export default function ScanPage({ onNewScan, onAudioPlay }: ScanPageProps) {
  const [projectName, setProjectName] = useState('');
  const [scanType, setScanType] = useState('full');
  const [inputMode, setInputMode] = useState<'file' | 'repo'>('file');
  const [isScanning, setIsScanning] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState('');
  const [scanError, setScanError] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [resultMessage, setResultMessage] = useState('');
  const [projectNameError, setProjectNameError] = useState('');
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'error' | 'info'>('error');
  const [toastVisible, setToastVisible] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const projectNameRef = useRef<HTMLInputElement>(null);
  const scanErrorRef = useRef<HTMLDivElement | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);

  const getRiskLevel = (score: number) => {
    if (score >= 80) return { label: 'Low Risk', color: '#6B8E63' };
    if (score >= 60) return { label: 'Medium Risk', color: '#D4A574' };
    if (score >= 40) return { label: 'High Risk', color: '#D84343' };
    return { label: 'Critical Risk', color: '#C94C4C' };
  };

  useEffect(() => {
    if (!isScanning || scanProgress >= 95) {
      return;
    }

    const timer = window.setInterval(() => {
      setScanProgress((prev) => Math.min(prev + Math.floor(Math.random() * 10) + 3, 95));
    }, 700);

    return () => window.clearInterval(timer);
  }, [isScanning, scanProgress]);

  const showToast = (message: string, type: 'error' | 'info' = 'error') => {
    setToastMessage(message);
    setToastType(type);
    setToastVisible(true);
    window.requestAnimationFrame(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    window.setTimeout(() => setToastVisible(false), 4200);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      const validTypes = [
        'application/zip',
        'application/x-zip-compressed',
        'application/javascript',
        'application/x-javascript',
        'application/ecmascript',
        'text/plain',
        'text/x-python',
        'text/javascript',
        'text/jsx',
        'text/typescript',
        'text/tsx',
        'text/x-java-source',
        'text/x-c',
        'text/x-c++src',
        'text/x-csharp',
        'text/html',
        'text/css',
        'application/xml',
        'application/json',
        'text/markdown',
      ];

      const supportedExtensions = ['zip', 'py', 'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'java', 'cpp', 'cc', 'c', 'cs', 'go', 'rb', 'php', 'swift', 'kt', 'kts', 'rs', 'sql', 'html', 'htm', 'xml', 'json', 'yaml', 'yml', 'css', 'scss', 'sass', 'less', 'vue', 'svelte', 'md', 'graphql', 'gql', 'env', 'ini'];
      const fileExtension = file.name.split('.').pop()?.toLowerCase() || '';
      const isValidExt = supportedExtensions.includes(fileExtension);
      const supportedTypeList = 'ZIP, Python, JavaScript, JSX, TSX, Java, C/C++, C#, Go, Ruby, PHP, Swift, Kotlin, Rust, SQL, HTML, XML, JSON, YAML, CSS, SCSS, SASS, LESS, Vue, Svelte, Markdown, GraphQL, Env, INI';

      console.log(`File validation: ${file.name}, ext=${fileExtension}, isValid=${isValidExt}, mimeType=${file.type}`);

      if (isValidExt || validTypes.includes(file.type)) {
        setSelectedFile(file);
        setScanError('');
        setProjectNameError('');
        console.log('File accepted:', file.name);
      } else {
        const errorMessage = `File type not supported. Upload ${supportedTypeList}.`;
        setScanError(errorMessage);
        showToast(errorMessage, 'error');
        setSelectedFile(null);
        console.log('File rejected:', file.name, 'ext:', fileExtension);
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError('');
    setProjectNameError('');
    
    if (!projectName.trim()) {
      setProjectNameError('Project name is required');
      setTimeout(() => {
        projectNameRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        projectNameRef.current?.focus();
      }, 50);
      return;
    }

    if (inputMode === 'file' && !selectedFile) {
      setScanError('Please select a file to scan');
      return;
    }

    if (inputMode === 'repo' && !repoUrl.trim()) {
      setScanError('Please enter a repository URL');
      return;
    }

    try {
      setIsScanning(true);
      if (onAudioPlay) onAudioPlay(true);
      
      await playScanchInitiatedSound();

      // Get API base URL (use import.meta.env for Vite)
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      
      let response;
      setScanProgress(20);

      if (inputMode === 'file') {
        // File upload mode
        const formData = new FormData();
        formData.append('file', selectedFile!);
        formData.append('project_name', projectName);
        formData.append('scan_type', scanType);

        response = await fetch(`${apiUrl}/api/v1/scans/upload`, {
          method: 'POST',
          body: formData,
        });
      } else {
        // Repository mode
        response = await fetch(`${apiUrl}/api/v1/scans/scan-repo`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            repository_url: repoUrl,
            project_name: projectName,
            scan_type: scanType,
          }),
        });
      }

      setScanProgress(60);

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || error.message || 'Scan failed');
      }

      const scanResult: ScanResult = await response.json();
      setScanProgress(100);

      // Play sound for findings based on severity
      if (scanResult.total_findings > 0) {
        const criticalCount = scanResult.severity_breakdown.critical || 0;
        const highCount = scanResult.severity_breakdown.high || 0;

        if (criticalCount > 0) {
          await playFindingSound('CRITICAL');
        } else if (highCount > 0) {
          await playFindingSound('HIGH');
        }
      }

      // Play completion sound
      await playScanCompleteSound();

      // Pass results to parent
      onNewScan(scanResult);
      setScanResult(scanResult);
      setReportUrl(`${apiUrl}/api/v1/scans/${scanResult.scan_id}/report?format=html`);
      setResultMessage('Scan completed successfully. Review the summary below or open the full report.');
      
      // Reset form fields but keep result visible
      setProjectName('');
      setScanType('full');
      setSelectedFile(null);
      setRepoUrl('');
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
      if (onAudioPlay) onAudioPlay(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'An error occurred during scanning';
      console.error('Scan error:', error);
      setScanError(message);
      showToast(message, 'error');
      setResultMessage('');
      if (onAudioPlay) onAudioPlay(false);
    } finally {
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  const downloadHtmlReport = async () => {
    if (!scanResult) return;
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    const response = await fetch(`${apiUrl}/api/v1/scans/${scanResult.scan_id}/report?format=html`);
    if (!response.ok) return;
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${scanResult.project_name || 'scan-report'}-${scanResult.scan_id}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  };

  const downloadPdfReport = () => {
    if (!reportUrl) return;
    const reportWindow = window.open(reportUrl, '_blank');
    if (reportWindow) {
      reportWindow.focus();
      reportWindow.onload = () => reportWindow.print();
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h2 className="page-title">New Scan</h2>
        <p className="page-subtitle">Upload your code archive or repository URL and scan with SecureHub's hybrid engine in one click.</p>
      </div>

      <div className="card">
        {toastVisible && (
          <div className="toast" style={{ backgroundColor: toastType === 'error' ? 'rgba(239, 68, 68, 0.95)' : 'rgba(14, 165, 233, 0.95)' }}>
            <div className="toast-icon">{toastType === 'error' ? '⚠️' : '✅'}</div>
            <div className="toast-content">
              <strong className="toast-title">{toastType === 'error' ? 'Upload Error' : 'Info'}</strong>
              <p className="toast-message">{toastMessage}</p>
            </div>
          </div>
        )}

        <h3 className="card-title">Start a New Scan</h3>
        <p className="page-subtitle">Upload code files or ZIP archives for vulnerability analysis</p>

        <form onSubmit={handleSubmit} className="scan-form">
          {scanError && <div className="alert alert-error"><p>{scanError}</p></div>}

          {/* Input Mode Selector */}
          <div className="form-group">
            <label className="form-label">Scan Source</label>
            <div className="input-mode-selector">
              {[
                { value: 'file', label: 'Upload File' },
                { value: 'repo', label: 'Repository URL' },
              ].map((option) => (
                <label key={option.value} className="input-mode-option">
                  <input
                    type="radio"
                    name="inputMode"
                    value={option.value}
                    checked={inputMode === (option.value as 'file' | 'repo')}
                    onChange={(e) => setInputMode(e.target.value as 'file' | 'repo')}
                    disabled={isScanning}
                  />
                  <span>{option.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* File Upload */}
          {inputMode === 'file' && (
            <div className="form-group">
              <label htmlFor="scan-file-input" className="form-label">Code File or ZIP Archive</label>
              <input
                ref={fileInputRef}
                id="scan-file-input"
                type="file"
                onChange={handleFileSelect}
                disabled={isScanning}
                accept=".zip,.py,.js,.jsx,.ts,.tsx,.mjs,.cjs,.java,.cpp,.cc,.c,.cs,.go,.rb,.php,.swift,.kt,.kts,.rs,.sql,.html,.htm,.xml,.json,.yaml,.yml,.css,.scss,.sass,.less,.vue,.svelte,.md,.graphql,.gql,.env,.ini"
                className="file-input-hidden"
              />
              <div className="file-input-wrapper">
                <label htmlFor="scan-file-input" className="btn btn-secondary">
                  {selectedFile ? 'Change File' : 'Choose File'}
                </label>
                <span className="file-name">{selectedFile ? selectedFile.name : 'No file selected. Supported: ZIP or code files.'}</span>
              </div>
              <p className="form-group-hint">{selectedFile ? 'Ready to scan the selected file.' : 'Supports ZIP files or individual code files.'}</p>
            </div>
          )}

          {/* Repository URL */}
          {inputMode === 'repo' && (
            <div className="form-group">
              <label className="form-label">Repository URL</label>
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo or https://gitlab.com/owner/repo"
                disabled={isScanning}
              />
              <p className="form-group-hint">Supports GitHub, GitLab, Gitea, and other Git repositories</p>
            </div>
          )}

          {/* Project Name */}
          <div className="form-group">
            <label htmlFor="project-name" className="form-label">Project Name <span className="required">*</span></label>
            <input
              ref={projectNameRef}
              id="project-name"
              type="text"
              value={projectName}
              onChange={(e) => {
                setProjectName(e.target.value);
                if (projectNameError) setProjectNameError('');
              }}
              placeholder="e.g., my-web-app"
              disabled={isScanning}
              aria-invalid={!!projectNameError}
            />
            {projectNameError && <p className="form-group-error">{projectNameError}</p>}
          </div>

          {/* Scan Progress */}
          {isScanning && (
            <div className="scan-progress">
              <p className="progress-text">Scanning in progress... {scanProgress}%</p>
              <div className="progress-bar">
                <div className="progress-bar-fill" style={{ width: `${scanProgress}%` }} />
              </div>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isScanning}
            className="btn btn-primary btn-lg"
            style={{ width: '100%', opacity: isScanning ? 0.6 : 1 }}
            onClick={async () => {
              if (!isScanning) await playButtonClickSound();
            }}
          >
            {isScanning ? `Scanning... ${scanProgress}%` : 'Start Scan'}
          </button>
        </form>

        {resultMessage && <div className="alert alert-info" style={{ marginTop: 'var(--space-6)' }}><p>{resultMessage}</p></div>}

        {scanResult && (
          <div ref={resultRef} className="card scan-result" style={{ marginTop: 'var(--space-6)' }}>
            <div className="scan-result-header">
              <div>
                <h2 className="card-title">Scan Complete</h2>
                <p className="page-subtitle">Project: <strong>{scanResult.project_name}</strong></p>
              </div>
              <div className="scan-result-duration">
                <div className="stat-label">Duration</div>
                <div className="stat-value">{scanResult.duration_seconds}s</div>
              </div>
            </div>

            <div className="scan-result-stats">
              <div className="result-stat">
                <div className="stat-label">Security Score</div>
                <div className="stat-value">{scanResult.security_score.toFixed(1)}%</div>
              </div>
              <div className="result-stat">
                <div className="stat-label">Findings</div>
                <div className="stat-value">{scanResult.total_findings}</div>
              </div>
              <div className="result-stat">
                <div className="stat-label">Risk Level</div>
                <div className="stat-value" style={{ color: getRiskLevel(scanResult.security_score).color }}>
                  {getRiskLevel(scanResult.security_score).label}
                </div>
              </div>
            </div>

            {reportUrl && (
              <div className="scan-result-actions">
                <button type="button" onClick={downloadHtmlReport} className="btn btn-primary">Download HTML Report</button>
                <button type="button" onClick={downloadPdfReport} className="btn btn-secondary">Save as PDF</button>
                <a href={reportUrl} target="_blank" rel="noreferrer" className="btn btn-secondary">Open Full Report</a>
                <button type="button" onClick={() => setScanResult(null)} className="btn btn-secondary">Clear Summary</button>
              </div>
            )}
          </div>
        )}

        <div className="alert alert-info" style={{ marginTop: 'var(--space-6)' }}>
          <p><strong>How it works:</strong> Upload a ZIP file containing your code repository or a single code file. Our hybrid detection engine will analyze the code for SQL injection, command injection, hardcoded secrets, and other vulnerabilities.</p>
        </div>
      </div>
    </div>
  );
}

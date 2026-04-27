import React, { useEffect, useState } from 'react';

interface AudioVisualizerProps {
  isPlaying: boolean;
  frequency?: number;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  duration?: number;
}

/**
 * Minimal geometric waveform visualizer
 * Bauhaus-style: sharp lines, no curves, pure geometric
 */
export const AudioVisualizer: React.FC<AudioVisualizerProps> = ({
  isPlaying,
  frequency = 440,
  severity = 'INFO',
  duration = 0.3,
}) => {
  const [bars, setBars] = useState<number[]>([]);

  useEffect(() => {
    if (!isPlaying) {
      setBars([]);
      return;
    }

    // Generate random bar heights for geometric visualization
    const numBars = 20;
    const newBars = Array.from({ length: numBars }, () => Math.random() * 80);
    setBars(newBars);

    // Clear after duration
    const timer = setTimeout(() => {
      setBars([]);
    }, duration * 1000);

    return () => clearTimeout(timer);
  }, [isPlaying, duration]);

  if (!isPlaying || bars.length === 0) return null;

  const colorMap = {
    CRITICAL: '#C94C4C',
    HIGH: '#D84343',
    MEDIUM: '#D4A574',
    LOW: '#617B8D',
    INFO: '#4A6FA5',
  };

  const color = colorMap[severity];
  const barWidth = 240 / bars.length;

  return (
    <div className="audio-visualizer audio-visualizer-active">
      <svg width="240" height="100" viewBox="0 0 240 100" xmlns="http://www.w3.org/2000/svg">
        {/* Center line */}
        <line x1="0" y1="50" x2="240" y2="50" stroke={color} strokeWidth="1" />

        {/* Frequency bars - geometric rectangular shapes */}
        {bars.map((height, i) => (
          <g key={i}>
            {/* Top bar */}
            <rect
              x={i * barWidth + 2}
              y={50 - height}
              width={barWidth - 4}
              height={height}
              fill={color}
              opacity="0.8"
            />
            {/* Bottom bar (mirrored) */}
            <rect
              x={i * barWidth + 2}
              y={50}
              width={barWidth - 4}
              height={height}
              fill={color}
              opacity="0.8"
            />
          </g>
        ))}
      </svg>
    </div>
  );
};

export default AudioVisualizer;

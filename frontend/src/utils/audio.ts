/**
 * Audio Synthesis Engine
 * Web Audio API - Generates tones and chords for UI feedback
 * No pre-recorded files, all generated dynamically
 */

interface AudioConfig {
  frequency?: number | number[];
  duration: number;
  volume?: number; // -20dB to -5dB
  type?: 'sine' | 'square' | 'triangle' | 'sawtooth';
}

let audioContext: AudioContext | null = null;
let isAudioEnabled = true;

export const initializeAudioContext = () => {
  if (!audioContext) {
    audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
  }
  return audioContext;
};

export const setAudioEnabled = (enabled: boolean) => {
  isAudioEnabled = enabled;
};

export const isAudioEnabledState = () => isAudioEnabled;

/**
 * Play a single tone with specified frequency
 */
export const playTone = async (config: AudioConfig) => {
  if (!isAudioEnabled) return;

  const ctx = initializeAudioContext();
  const volume = config.volume || -12; // dB
  const gainValue = Math.pow(10, volume / 20); // Convert dB to linear
  const frequency = Array.isArray(config.frequency) ? config.frequency[0] : config.frequency;

  if (!isFinite(frequency)) {
    console.warn('[audio] Invalid tone frequency:', config.frequency);
    return;
  }

  const oscillator = ctx.createOscillator();
  const gainNode = ctx.createGain();

  oscillator.type = config.type || 'sine';
  oscillator.frequency.value = frequency;
  gainNode.gain.value = isFinite(gainValue) ? gainValue : 0.0;

  oscillator.connect(gainNode);
  gainNode.connect(ctx.destination);

  oscillator.start(ctx.currentTime);
  oscillator.stop(ctx.currentTime + config.duration);

  return new Promise((resolve) => {
    setTimeout(resolve, config.duration * 1000);
  });
};

/**
 * Play a sequence of tones (melody)
 */
export const playSequence = async (frequencies: number[], duration: number, volume?: number) => {
  if (!isAudioEnabled) return;

  const ctx = initializeAudioContext();
  const gainValue = Math.pow(10, (volume || -12) / 20);

  for (const freq of frequencies) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.value = freq;
    gain.gain.value = gainValue;

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + duration);

    await new Promise((resolve) => setTimeout(resolve, duration * 1000));
  }
};

/**
 * Play a chord (multiple frequencies simultaneously)
 */
export const playChord = async (frequencies: number[], duration: number, volume?: number) => {
  if (!isAudioEnabled) return;

  const ctx = initializeAudioContext();
  const gainValue = Math.pow(10, (volume || -12) / 20);

  const oscillators = frequencies.map((freq) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.value = freq;
    gain.gain.value = gainValue;

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(ctx.currentTime);

    return { osc, gain, duration };
  });

  await new Promise((resolve) => {
    setTimeout(() => {
      oscillators.forEach(({ osc }) => osc.stop());
      resolve(null);
    }, duration * 1000);
  });
};

/**
 * UI Event Sounds
 */

// Scan initiated - deep, resonant tone
export const playScanchInitiatedSound = () => {
  return playTone({ frequency: 150, duration: 0.3, volume: -12 });
};

// Finding detected sounds based on severity
export const playFindingSound = (severity: string) => {
  const upperSeverity = severity.toUpperCase();
  const frequencies: Record<string, number> = {
    CRITICAL: 800, // Harsh, sharp
    HIGH: 600, // Medium tone
    MEDIUM: 400, // Softer tone
    LOW: 300, // Subtle chime
  };

  const durations: Record<string, number> = {
    CRITICAL: 0.1,
    HIGH: 0.15,
    MEDIUM: 0.15,
    LOW: 0.1,
  };

  return playTone({
    frequency: frequencies[upperSeverity] ?? 440,
    duration: durations[upperSeverity] ?? 0.15,
    volume: -12,
  });
};

// Scan complete - rising tone sequence
export const playScanCompleteSound = () => {
  return playSequence([200, 400, 300], 0.15, -12);
};

// Button hover - subtle frequency shift
export const playButtonHoverSound = () => {
  return playTone({ frequency: 450, duration: 0.05, volume: -15 });
};

// Button click - short, percussive
export const playButtonClickSound = () => {
  return playTone({ frequency: 1000, duration: 0.05, volume: -12 });
};

// Error - discord chord (C-E-G - dissonant)
export const playErrorSound = () => {
  return playChord([261.63, 329.63, 392.0], 0.3, -12); // C, E, G
};

// Success - perfect fifth (C-G)
export const playSuccessSound = () => {
  return playChord([261.63, 392.0], 0.4, -12); // C, G (perfect fifth)
};

/**
 * Frequency mapping for intervals
 */
export const frequencies = {
  C: 261.63,
  D: 293.66,
  E: 329.63,
  F: 349.23,
  G: 392.0,
  A: 440.0,
  B: 493.88,
};

/**
 * Generate waveform visualization data
 * Returns points for SVG path for geometric visualization
 */
export const generateWaveformData = (frequency: number, duration: number, sampleRate = 100) => {
  const samples = duration * sampleRate;
  const amplitude = 30; // Pixel height
  const centerY = 50;
  const points: string[] = [];

  for (let i = 0; i < samples; i++) {
    const x = (i / samples) * 200; // 200px width
    const y = centerY + amplitude * Math.sin((i / samples) * Math.PI * 4 * (frequency / 440));
    points.push(`${x},${y}`);
  }

  return points.join(' ');
};

/**
 * Frequency visualization (vertical bars)
 */
export const generateFrequencyBars = (frequencies: number[]) => {
  const width = 200;
  const height = 100;
  const barWidth = width / frequencies.length;
  const maxFreq = Math.max(...frequencies);

  return frequencies.map((freq, i) => {
    const barHeight = (freq / maxFreq) * height;
    const x = i * barWidth;
    const y = height - barHeight;
    return { x, y, width: barWidth - 2, height: barHeight };
  });
};

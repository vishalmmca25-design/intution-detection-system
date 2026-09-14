import './FlowTrace.css';

// Three hand-drawn traces: a calm regular wave (benign), a jagged erratic
// one (attack — bursty tiny packets, near-zero gaps), and a neutral idle
// sine wave shown before anything has been analyzed.
const PATHS = {
  idle: 'M0,40 C 30,15 60,15 90,40 C 120,65 150,65 180,40 C 210,15 240,15 270,40 C 300,65 330,65 360,40 C 390,15 420,15 450,40 C 480,65 510,65 540,40 C 560,25 580,25 600,40',
  scanning: 'M0,40 C 15,10 25,70 35,15 C 45,68 55,12 65,55 C 75,20 85,60 95,18 C 105,62 115,15 125,58 C 135,22 145,65 155,20 C 165,60 175,15 185,55 C 195,25 205,60 215,18 C 225,58 235,20 245,60 C 255,15 265,58 275,22 C 285,60 295,18 305,55 C 315,25 325,58 335,20 C 345,60 355,15 365,55 C 375,22 385,58 395,20 C 405,58 415,18 425,55 C 435,25 445,60 455,18 C 465,58 475,20 485,58 C 495,22 505,58 515,20 C 525,58 535,18 545,55 C 555,25 565,58 575,20 C 585,55 592,25 600,40',
  safe: 'M0,40 C 40,28 80,28 120,40 C 160,52 200,52 240,40 C 280,28 320,28 360,40 C 400,52 440,52 480,40 C 520,28 560,28 600,40',
  alert: 'M0,40 L20,10 L30,68 L45,18 L55,60 L70,12 L80,64 L95,20 L105,58 L120,14 L128,66 L145,22 L155,58 L170,10 L180,68 L195,18 L205,60 L220,14 L230,64 L245,20 L255,58 L270,12 L280,66 L295,20 L305,58 L320,15 L330,65 L345,20 L355,58 L370,12 L380,64 L395,18 L405,60 L420,14 L430,66 L445,20 L455,58 L470,10 L480,68 L495,18 L505,60 L520,14 L530,64 L545,20 L555,58 L570,12 L580,66 L590,25 L600,40',
};

const COLORS = {
  idle: 'var(--accent-cyan)',
  scanning: 'var(--accent-amber)',
  safe: 'var(--accent-safe)',
  alert: 'var(--accent-alert)',
};

export default function FlowTrace({ state = 'idle' }) {
  const color = COLORS[state] || COLORS.idle;
  return (
    <div className={`flow-trace flow-trace--${state}`} aria-hidden="true">
      <svg viewBox="0 0 600 80" preserveAspectRatio="none">
        <path
          d={PATHS[state] || PATHS.idle}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

<script setup>
import Dashboard from './components/Dashboard.vue';
</script>

<template>
  <Dashboard />
</template>

<style>
:root {
  /* Deep slate/ink background + signal amber/red accents */
  --ink-900: #080b11;
  --ink-800: #0d121b;
  --ink-700: #131a26;
  --ink-600: #1a2331;
  --line: #223044;
  --line-soft: #1a2432;

  --text: #dde5f0;
  --text-dim: #93a1b8;
  --text-faint: #6b7a92;

  --amber: #f0a92b;
  --amber-dim: #7a5613;
  --red: #f0553d;
  --red-dim: #7d2a1c;
  --teal: #3fb9a3;
  --teal-dim: #1d5750;

  --mono: ui-monospace, 'JetBrains Mono', 'SFMono-Regular', 'Cascadia Mono', Consolas,
    'Liberation Mono', monospace;
  --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
}

* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  padding: 0;
  background: var(--ink-900);
  color: var(--text);
  font-family: var(--sans);
  -webkit-font-smoothing: antialiased;
}

#app {
  min-height: 100vh;
}

::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}
::-webkit-scrollbar-track {
  background: var(--ink-900);
}
::-webkit-scrollbar-thumb {
  background: var(--ink-600);
  border-radius: 5px;
}
::-webkit-scrollbar-thumb:hover {
  background: #2a3548;
}
</style>

(function(){
  const rawPath = window.location.pathname.replace(/\/$/, '') || '/';
  const path = rawPath.startsWith('/public/') ? rawPath.replace('/public', '') : (rawPath === '/public' ? '/' : rawPath);
  document.querySelectorAll('.links a[data-path]').forEach((a) => {
    const target = a.getAttribute('data-path');
    if (target === path) a.classList.add('active');
  });

  const stageInput = document.getElementById('stageInput');
  if (!stageInput) return;

  const stageTitle = document.getElementById('stageTitle');
  const stageText = document.getElementById('stageText');
  const stageTags = document.getElementById('stageTags');

  const stageData = [
    {
      title: '1) Collect Signals',
      text: 'HexHawk pulls structural and behavioral hints from binaries and scripts, so analysts start with evidence instead of raw noise.',
      tags: ['Strings', 'Headers', 'Imports']
    },
    {
      title: '2) Build Hypotheses',
      text: 'TALON and ECHO generate explanations and alternate theories, then check for contradictions to avoid tunnel vision.',
      tags: ['TALON', 'ECHO', 'Confidence']
    },
    {
      title: '3) Validate on Challenges',
      text: 'STRIKE evaluates detections against adversarial samples so teams can trust what ships to clients.',
      tags: ['STRIKE', 'Regression', 'Benchmarks']
    },
    {
      title: '4) Deliver Client-Ready Output',
      text: 'NEST and report layers produce explainable findings with evidence trails suitable for stakeholder and customer review.',
      tags: ['NEST', 'Evidence', 'Reports']
    }
  ];

  function renderStage(index) {
    const clamped = Math.max(0, Math.min(stageData.length - 1, index));
    const active = stageData[clamped];
    stageInput.value = String(clamped);
    stageInput.setAttribute('aria-valuetext', active.title);
    if (stageTitle) stageTitle.textContent = active.title;
    if (stageText) stageText.textContent = active.text;
    if (stageTags) {
      stageTags.innerHTML = active.tags.map((tag) => `<span class="pill">${tag}</span>`).join('');
    }

    document.querySelectorAll('[data-stage-node]').forEach((node) => {
      const nodeIndex = Number(node.getAttribute('data-stage-node'));
      node.classList.toggle('active', nodeIndex <= clamped);
    });

    document.querySelectorAll('[data-stage-line]').forEach((line) => {
      const lineIndex = Number(line.getAttribute('data-stage-line'));
      line.classList.toggle('active', lineIndex < clamped);
    });

    document.querySelectorAll('[data-stage-jump]').forEach((btn) => {
      const value = Number(btn.getAttribute('data-stage-jump'));
      btn.classList.toggle('active', value === clamped);
    });
  }

  stageInput.addEventListener('input', () => {
    renderStage(Number(stageInput.value));
  });

  stageInput.addEventListener('change', () => {
    renderStage(Number(stageInput.value));
  });

  document.querySelectorAll('[data-stage-jump]').forEach((btn) => {
    btn.addEventListener('click', () => {
      renderStage(Number(btn.getAttribute('data-stage-jump')));
    });
  });

  renderStage(Number(stageInput.value || '0'));
})();

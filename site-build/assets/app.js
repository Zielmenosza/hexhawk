(function(){
  const rawPath = window.location.pathname.replace(/\/$/, '') || '/';
  const path = rawPath.startsWith('/public/') ? (rawPath.replace('/public', '') || '/') : rawPath;
  document.querySelectorAll('.links a[data-path]').forEach((a) => {
    const target = a.getAttribute('data-path');
    if (target === path || (target !== '/' && path.startsWith(target))) a.classList.add('active');
  });
  const toggle = document.querySelector('.nav-toggle');
  const links = document.querySelector('.links');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      const open = links.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
  }
})();

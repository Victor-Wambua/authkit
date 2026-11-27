// Points the repository's web UI at the in-page service. The UI calls fetch('/api/...');
// here those calls go to the demo host in the parent page instead of the network.
(function () {
  var host = window.parent !== window ? window.parent.__authkitDemo : null;
  if (!host) {
    document.addEventListener('DOMContentLoaded', function () {
      document.body.textContent = 'This view runs inside the demo page. Open the demo page instead.';
    });
    return;
  }
  window.__AUTHKIT_DEMO__ = true;
  var nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : input.url;
    return /^\/api\//.test(url) ? host.fetch(input, init, 'web app') : nativeFetch(input, init);
  };
})();

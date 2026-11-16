/*
 * The pages ask the OnlyKey to sign, decrypt and derive, so they run only as
 * the top-level page. A <meta> CSP cannot set frame-ancestors and GitHub Pages
 * sends no X-Frame-Options, so the page checks for itself.
 *
 * Plain CommonJS with no imports so it can be checked in Node.
 */
'use strict';

function framed(win) {
  try {
    return win.top !== win.self;
  } catch (e) {
    return true;
  }
}

/** Returns true, after hiding the page and trying to leave the frame, when framed. */
function refuseFramed(win) {
  if (!framed(win)) return false;
  win.document.documentElement.style.display = 'none';
  try {
    win.top.location = win.location.href;
  } catch (e) {}
  return true;
}

module.exports = { framed: framed, refuseFramed: refuseFramed };

/*
 * How a PGP key is named to the user.
 *
 * A key is shown by its whole primary user ID, the number of other user IDs,
 * and its full fingerprint. Control characters are dropped (the text also goes
 * to the xterm log), and so are invisible and direction-changing characters.
 *
 * Plain CommonJS with no imports so it can be checked in Node.
 */
'use strict';

var HIDDEN = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;

function clean(s) {
  return String(s).replace(HIDDEN, '');
}

function fingerprint(km) {
  return km.get_pgp_fingerprint().toString('hex').toUpperCase().match(/.{4}/g).join(' ');
}

/** The primary user ID, plus how many others the key carries. */
function userid(km) {
  var ids;
  try {
    ids = km.get_userids_mark_primary();
  } catch (e) {
    ids = km.get_userids ? km.get_userids() : [];
  }
  var pick = null;
  for (var i = 0; i < ids.length; i++) {
    if (ids[i] && ids[i].primary) { pick = ids[i]; break; }
  }
  if (!pick && ids.length) pick = ids[0];
  if (!pick || !pick.utf8) return '(no user ID)';
  return clean(pick.utf8()) + (ids.length > 1 ? ' (+' + (ids.length - 1) + ' more)' : '');
}

/** "Alice <alice@example.org> [ABCD 1234 ... 40 hex digits]" */
function describe(km) {
  return userid(km) + ' [' + fingerprint(km) + ']';
}

/** The same line for an openpgp.js key (the openpgp.js decrypt route). */
function describeOpenpgp(key) {
  var ids = [];
  try { ids = key.getUserIDs(); } catch (e) { ids = []; }
  var uid = ids.length ? clean(ids[0]) + (ids.length > 1 ? ' (+' + (ids.length - 1) + ' more)' : '') : '(no user ID)';
  var fp = String(key.getFingerprint()).toUpperCase().match(/.{4}/g).join(' ');
  return uid + ' [' + fp + ']';
}

module.exports = { describe: describe, describeOpenpgp: describeOpenpgp, fingerprint: fingerprint, userid: userid };

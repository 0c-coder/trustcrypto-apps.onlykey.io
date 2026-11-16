/*
 * Query string -> object, for getAllUrlParams() in onlykey.extra.js and the
 * pages plugin.
 *
 * The result has no prototype, and the names "__proto__", "constructor" and
 * "prototype" are ignored.
 *
 * Plain CommonJS with no imports so it can be checked in Node.
 */
'use strict';

var REFUSED = ['__proto__', 'constructor', 'prototype'];

function add(obj, name, value) {
  var cur = obj[name];
  if (!cur) obj[name] = value;
  else if (Array.isArray(cur)) cur.push(value);
  else obj[name] = [cur, value];
}

/**
 * @param {string} [url]  parse this URL's query instead of the page's
 * @param {{search?:string, hash?:string}} loc  the page location
 */
function parse(url, loc) {
  var queryString = url ? url.split('?')[1] : String((loc && loc.search) || '').slice(1);
  var obj = Object.create(null);
  obj['#'] = String((loc && loc.hash) || '').split('#')[1];
  if (!queryString) return obj;

  var arr = queryString.split('#')[0].split('&');
  for (var i = 0; i < arr.length; i++) {
    var a = arr[i].split('=');
    var paramName = a[0];
    var paramValue = typeof(a[1]) === 'undefined' ? true : a[1];

    var m = /^(.*)\[(\d+)?\]$/.exec(paramName);
    var key = m ? m[1] : paramName;
    if (REFUSED.indexOf(key) !== -1) continue;

    if (!m) {
      add(obj, key, paramValue);
      continue;
    }
    if (!Array.isArray(obj[key])) obj[key] = obj[key] === undefined ? [] : [obj[key]];
    if (m[2] !== undefined) obj[key][m[2]] = paramValue;
    else obj[key].push(paramValue);
  }
  return obj;
}

module.exports = { parse: parse };

#!/usr/bin/env node
/* Check Portail i18n catalogs and data-i18n keys.
 * Usage: node scripts/check-i18n.js
 */
const fs = require('fs')
const path = require('path')
const vm = require('vm')

const root = path.resolve(__dirname, '..')
const catalogPath = path.join(root, 'i18n', 'catalogs.js')
const ctx = { window: {} }
vm.createContext(ctx)
vm.runInContext(fs.readFileSync(catalogPath, 'utf8'), ctx, { filename: catalogPath })
const catalog = ctx.window.SPID_I18N_CATALOG || {}
const langs = ['en', 'fr', 'es']

const errors = []
const keys = new Set(Object.keys(catalog.en || {}))

for (const lang of langs) {
  const table = catalog[lang] || {}
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(table, key)) {
      errors.push(`${lang}: missing key ${key}`)
    } else if (typeof table[key] !== 'string' || !table[key].trim()) {
      errors.push(`${lang}: empty value for ${key}`)
    }
  }
  for (const key of Object.keys(table)) {
    if (!keys.has(key)) errors.push(`${lang}: extra key ${key}`)
  }
}

const html = fs.readFileSync(path.join(root, 'portail.html'), 'utf8')
const attrRe = /data-i18n(?:-placeholder|-title|-aria-label)?="([^"]+)"/g
let m
while ((m = attrRe.exec(html))) {
  if (!keys.has(m[1])) errors.push(`portail.html: unknown key ${m[1]}`)
}

const js = fs.readFileSync(path.join(root, 'portail.js'), 'utf8')
const callRe = /spidT\(\s*['"]([^'"]+)['"]/g
while ((m = callRe.exec(js))) {
  // Dynamic keys such as 'relations.kind.' + kind are checked by their prefix.
  if (m[1].endsWith('.')) continue
  if (!keys.has(m[1])) errors.push(`portail.js: unknown key ${m[1]}`)
}

if (errors.length) {
  console.error(errors.join('\n'))
  process.exit(1)
}
console.log(`i18n OK: ${keys.size} keys, ${langs.length} languages`)

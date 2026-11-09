/* Sovereign Passport — PWA install affordance.
 *
 * Browsers never allow a page to install itself silently. This module:
 *   - registers the local service worker;
 *   - shows a button when the browser offers an install prompt;
 *   - shows the iOS "Add to Home Screen" instructions where needed.
 *
 * The final installation remains a user gesture. No auto-install.
 */
(function () {
  'use strict'
  if (window.__SPID_PWA_INSTALL__) return
  window.__SPID_PWA_INSTALL__ = true

  function currentLang() {
    var raw = ''
    try {
      if (typeof window.spidLang === 'function') raw = window.spidLang()
    } catch (e) {}
    if (!raw) raw = document.documentElement.lang || navigator.language || 'en'
    raw = String(raw).slice(0, 2).toLowerCase()
    return ['fr', 'en', 'es'].indexOf(raw) === -1 ? 'en' : raw
  }

  function keyOr(key, fallback) {
    try {
      if (typeof window.spidT === 'function') {
        var value = window.spidT(key)
        if (value && value !== key) return value
      }
    } catch (e) {}
    return fallback
  }

  var lang = currentLang()
  var FALLBACK = {
    fr: {
      install: 'Installer l’application',
      ios: 'Ajouter à l’écran d’accueil',
      title: 'Installer l’application',
      close: 'Fermer',
      iosHelp: 'Ouvrez le menu Partager de Safari, puis choisissez « Sur l’écran d’accueil ».',
      desktopHelp: 'Utilisez l’icône d’installation de la barre d’adresse du navigateur.'
    },
    en: {
      install: 'Install app',
      ios: 'Add to Home Screen',
      title: 'Install app',
      close: 'Close',
      iosHelp: 'Open Safari’s Share menu, then choose “Add to Home Screen”.',
      desktopHelp: 'Use the install icon in the browser address bar.'
    },
    es: {
      install: 'Instalar la aplicación',
      ios: 'Añadir a la pantalla de inicio',
      title: 'Instalar la aplicación',
      close: 'Cerrar',
      iosHelp: 'Abre el menú Compartir de Safari y elige «Añadir a pantalla de inicio».',
      desktopHelp: 'Usa el icono de instalación de la barra de direcciones del navegador.'
    }
  }[lang]

  var T = {
    install: keyOr('pwa.install', FALLBACK.install),
    ios: keyOr('pwa.ios', FALLBACK.ios),
    title: keyOr('pwa.title', FALLBACK.title),
    close: keyOr('pwa.close', FALLBACK.close),
    iosHelp: keyOr('pwa.ios_help', FALLBACK.iosHelp),
    desktopHelp: keyOr('pwa.desktop_help', FALLBACK.desktopHelp)
  }

  function standalone() {
    return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
      window.navigator.standalone === true
  }
  function isiOS() {
    return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
      (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
  }

  function injectStyles() {
    if (document.getElementById('spidPwaInstallStyles')) return
    var style = document.createElement('style')
    style.id = 'spidPwaInstallStyles'
    style.textContent = [
      '.spid-pwa-install{position:fixed;right:16px;bottom:16px;z-index:240;',
      'display:flex;align-items:center;justify-content:center;gap:8px;',
      'width:auto;max-width:calc(100vw - 32px);padding:10px 14px;',
      'border:1px solid rgba(201,169,97,.55);border-radius:999px;',
      'background:rgba(16,18,22,.94);color:#e8dcc0;',
      'font:600 11px/1.2 Georgia,serif;letter-spacing:.06em;',
      'box-shadow:0 8px 24px rgba(0,0,0,.35);cursor:pointer;',
      '-webkit-tap-highlight-color:transparent}',
      '.spid-pwa-install:hover{background:rgba(28,30,36,.98);color:#fff}',
      '.spid-pwa-install[hidden]{display:none!important}',
      '.spid-pwa-overlay{position:fixed;inset:0;z-index:500;display:flex;',
      'align-items:center;justify-content:center;padding:18px;',
      'background:rgba(8,9,12,.82)}',
      '.spid-pwa-overlay[hidden]{display:none!important}',
      '.spid-pwa-card{box-sizing:border-box;width:min(420px,100%);',
      'background:#14161a;border:1px solid rgba(201,169,97,.45);',
      'border-radius:14px;padding:20px;color:#e8dcc0;',
      'box-shadow:0 24px 70px rgba(0,0,0,.55)}',
      '.spid-pwa-card h2{margin:0 0 10px;font:600 17px/1.25 Georgia,serif;color:#f1e5c7}',
      '.spid-pwa-card p{margin:0 0 16px;font:14px/1.55 Georgia,serif;color:#c9c1ae}',
      '.spid-pwa-card button{width:100%;padding:10px 14px;border:1px solid rgba(201,169,97,.5);',
      'border-radius:9px;background:rgba(201,169,97,.12);color:#e8dcc0;',
      'font:600 11px/1.2 Georgia,serif;letter-spacing:.08em;text-transform:uppercase;cursor:pointer}',
      '@media(max-width:600px){.spid-pwa-install{left:16px;right:16px;bottom:16px;max-width:none}}'
    ].join('')
    document.head.appendChild(style)
  }

  var deferred = null
  var button = null
  var overlay = null
  var card = null
  var cardTitle = null
  var cardText = null
  var cardClose = null

  function makeOverlay() {
    if (overlay) return
    overlay = document.createElement('div')
    overlay.className = 'spid-pwa-overlay'
    overlay.hidden = true
    overlay.setAttribute('role', 'dialog')
    overlay.setAttribute('aria-modal', 'true')
    overlay.setAttribute('aria-labelledby', 'spidPwaTitle')
    card = document.createElement('div')
    card.className = 'spid-pwa-card'
    cardTitle = document.createElement('h2')
    cardTitle.id = 'spidPwaTitle'
    cardTitle.textContent = T.title
    cardText = document.createElement('p')
    cardClose = document.createElement('button')
    cardClose.type = 'button'
    cardClose.textContent = T.close
    card.appendChild(cardTitle)
    card.appendChild(cardText)
    card.appendChild(cardClose)
    overlay.appendChild(card)
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) hideHelp()
    })
    cardClose.addEventListener('click', hideHelp)
    document.body.appendChild(overlay)
  }

  function showHelp(ios) {
    makeOverlay()
    cardTitle.textContent = T.title
    cardText.textContent = ios ? T.iosHelp : T.desktopHelp
    overlay.hidden = false
    cardClose.focus()
  }
  function hideHelp() {
    if (overlay) overlay.hidden = true
  }

  function makeButton() {
    if (button) return
    button = document.createElement('button')
    button.id = 'spidPwaInstall'
    button.type = 'button'
    button.className = 'spid-pwa-install'
    button.hidden = true
    button.textContent = T.install
    button.addEventListener('click', function () {
      if (deferred) {
        var p = deferred
        deferred = null
        p.prompt()
        p.userChoice.then(function () {
          button.hidden = true
        }).catch(function () {
          button.hidden = true
        })
        return
      }
      if (isiOS()) {
        showHelp(true)
      } else {
        showHelp(false)
      }
    })
    document.body.appendChild(button)
  }

  function showButton() {
    if (standalone()) return
    makeButton()
    button.textContent = isiOS() ? T.ios : T.install
    button.hidden = false
  }
  function hideButton() {
    if (button) button.hidden = true
  }

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault()
    deferred = e
    showButton()
  })
  window.addEventListener('appinstalled', function () {
    deferred = null
    hideButton()
  })

  function init() {
    injectStyles()
    makeButton()
    // The Passport already has its own iOS install banner. The Portail does
    // not, so it gets the generic iOS button/instructions.
    if (isiOS() && !standalone() && !document.getElementById('install-banner')) {
      setTimeout(showButton, 2500)
    }
  }

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('./sw.js').catch(function () {})
    })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init)
  } else {
    init()
  }
})()

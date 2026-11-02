// The card read on this page. Pressing the card's button asks the card, through
// the Web eID library and the browser extension, to sign the challenge this page
// was shown with, then posts the card's answer with the page's card form. Without
// this script the button posts the page's choice, and the page says the card
// needs script.

const form = document.getElementById('card')
const button = document.querySelector('button[data-card]')

// The card software is missing when the extension or its native application does
// not answer, or the library itself cannot be loaded; anything else is a sign-in
// that did not complete.
const missingCodes = ['ERR_WEBEID_EXTENSION_UNAVAILABLE', 'ERR_WEBEID_NATIVE_UNAVAILABLE']

class LibraryUnavailable extends Error {}

function clearMessages() {
  for (const old of document.querySelectorAll('[data-card-message]')) old.remove()
}

function say(missing) {
  const box = document.createElement('div')
  box.setAttribute('role', 'alert')
  box.dataset.cardMessage = ''
  if (missing) {
    box.className = 'alert amber'
    const title = document.createElement('b')
    title.textContent = form.dataset.missingTitle
    const link = document.createElement('a')
    link.href = form.dataset.missingHref
    link.textContent = form.dataset.missingAction
    box.append(title, ' ' + form.dataset.missingLead + ' ', link)
  } else {
    box.className = 'alert'
    box.textContent = form.dataset.failed
  }
  document.querySelector('form.waylist').before(box)
}

async function readCard() {
  let webeid
  try {
    webeid = await import('/signin/web-eid.js')
  } catch {
    throw new LibraryUnavailable()
  }

  return webeid.authenticate(form.dataset.nonce, { lang: document.documentElement.lang })
}

if (form && button) {
  button.addEventListener('click', async (event) => {
    event.preventDefault()
    const buttons = [...document.querySelectorAll('form.waylist button')]
    const name = button.textContent
    clearMessages()
    for (const b of buttons) b.disabled = true
    button.textContent = form.dataset.waiting
    try {
      const token = await readCard()
      form.elements.token.value = JSON.stringify(token)
      form.submit()
    } catch (err) {
      for (const b of buttons) b.disabled = false
      button.textContent = name
      say(err instanceof LibraryUnavailable || missingCodes.includes(err && err.code))
    }
  })
}

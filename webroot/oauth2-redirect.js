(function(){
  const params = new URLSearchParams((location.hash || location.search).substr(1));

  history.replaceState(null, '', '/');

  if (!params.has('state')) {
    return opener.postMessage({
      id: null,
      ok: false,
      data: {
        error: o.error,
        description: o.error_description,
      }
    });
  }

  const encoder = new TextEncoder();

  const [ id, key ] = params.get('state').split(':');
  params.delete('state');

  const plaintext = params.toString();

  const ts = new Date().getTime() + new Date().getTimezoneOffset();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));

  crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    {
      name: 'PBKDF2'
    },
    false,
    ['deriveKey']
  ).then(key => {
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 1000,
        hash: {
          name: 'SHA-256'
        }
      },
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt']
    )
  }).then(key => {
    return crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: encoder.encode(ts)
      },
      key,
      encoder.encode(plaintext)
    )
  }).then(ciphertext => {
    opener.postMessage({
      id: id,
      ok: true,
      ts: ts,
      salt: salt,
      iv: iv,
      data: ciphertext
    });
  });
}).call(this);

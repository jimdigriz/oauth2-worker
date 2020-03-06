function a2qs(a) {
	// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
	function fixedEncodeURIComponent(str) {
		return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
			return '%' + c.charCodeAt(0).toString(16);
		});
	}

	let qs = [];
	for (let i = 0; i < a.length; i++)
		if (a[i][1] !== undefined && a[i][1] !== null && a[i][1] !== false)
			qs.push(fixedEncodeURIComponent(a[i][0]) + (a[i][1] !== true ? ('=' + fixedEncodeURIComponent(a[i][1])) : ''));
	return qs.join('&');
}

// https://stackoverflow.com/a/2117523
function uuidv4() {
	return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
		(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
	);
}

// https://stackoverflow.com/a/42334410
function ab2bstr(ab) {
	return new Uint8Array(ab).reduce((data, byte) => {
		return data + String.fromCharCode(byte);
	}, '');
}

function base64url_encode(s) {
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64url_decode(s) {
	return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

const pending = {};

let config = null;
function init(data) {
	data.data.scopes = data.data.scopes || [];

	config = new Promise((resolve, reject) => {
		fetch(data.data.discovery_endpoint + '/.well-known/openid-configuration').then(
			response => {
				if (!response.ok) throw new Error(response.statusText);
				return response.json();
			}
		).then(
			json => {
				if (!(json.response_types_supported.includes('code') || json.response_types_supported.includes('token'))) throw new Error("only 'code' and 'token' supported");
				const overlap = data.data.scopes.filter(scope => json.scopes_supported.includes(scope));
				if (overlap.length < data.data.scopes.length) throw new Error('scopes not available');
				data.data.openid = json;
				resolve(data.data);
			}
		).catch(
			e => {
				reject(null);
				throw new Error('discovery: ' + e.message);
			}
		);
	});
}

let _tokens = null;
function tokens(tokens) {
	if (_tokens instanceof Promise)
		return _tokens;

	const id = uuidv4();
	// https://tools.ietf.org/html/rfc7636#section-4.1
	const code_verifier = base64url_encode(ab2bstr(crypto.getRandomValues(new Uint8Array(32))));

	const redirect = new Promise((resolve, reject) => {
		pending[id] = { resolve: resolve, reject: reject };
	});
	const digest = crypto.subtle.digest(
		{
			name: 'SHA-256'
		},
		(new TextEncoder()).encode(code_verifier)
	);
	Promise.all([config, digest]).then(
		args => {
			const [config, code_challenge] = args;

			const a = [
				[ 'client_id',		config.client_id ],
				[ 'redirect_uri',	location.origin + config.redirect_uri ],
				[ 'state',		id ],
				[ 'scope',		config.scopes.length ? config.scopes.join(' ') : undefined ]
			];
			if (config.openid.token_endpoint) {
				a.push(
					[ 'response_type',		'code' ],
					[ 'code_challenge_method',	'S256' ],
					[ 'code_challenge',		base64url_encode(ab2bstr(code_challenge)) ]
				);
			} else {
				a.push(
					[ 'response_type',		'token' ],
				);
			}

			postMessage({ type: 'authorize', id: id, data: {
				uri: config.openid.authorization_endpoint + '?' + a2qs(a)
			}});
	});

	_tokens = new Promise((resolve, reject) => {
		Promise.all([config, redirect]).then(args => {
			const [ config, redirect ] = args;

			if (redirect.data.access_token) {
				resolve(redirect.data);
				postMessage({ id: redirect.id, ok: true });
				return;
			}

			const params = [
				[ 'client_id', config.client_id ]
			];
			if (config.client_secret && config.openid.token_endpoint_auth_methods_supported.includes('client_secret_post'))
				params.push(['client_secret', config.client_secret]);
//			if (redirect.data.code) {
				params.push(
					[ 'grant_type',		'authorization_code' ],
					[ 'redirect_uri',	location.origin + config.redirect_uri ],
					[ 'code',		redirect.data.code ],
					[ 'code_verifier',	code_verifier ]
				);
//			} else if (tokens.refresh) {
//				params.push(
//					[ 'grant_type',		'refresh_token' ],
//					[ 'refresh_token',	tokens.refresh ]
//				);
//			}

			const headers = {
				'content-type': 'application/x-www-form-urlencoded'
			};
			if (config.client_secret && config.openid.token_endpoint_auth_methods_supported.includes('client_secret_basic'))
				headers['authorization'] = 'Basic ' + btoa(config.client_id + ':' + config.client_secret);
			fetch(config.openid.token_endpoint, {
				method: 'POST',
				headers: headers,
				body: a2qs(params)
			}).then(
				response => {
					if (!response.ok) throw new Error(response.statusText);
					return response.json();
				}
			).then(
				json => {
					resolve(json);
					postMessage({ id: redirect.id, ok: true });
				}
			).catch(
				error => {
					console.error('redirect', error.message);
					reject(null);
					postMessage({ id: redirect.id, ok: false, data: { error: error.message } });
				}
			);
		});
	});

	return _tokens;
}

function _do_fetch(data) {
	return tokens().then(tokens => {
		data.data.options = data.data.options || {};
		data.data.options.headers = data.data.options.headers || {};
		data.data.options.headers['authorization'] = [ tokens.type, tokens.access ].join(' ');

		return fetch(data.data.uri, data.data.options).then(
			response => {
				if (response.status == 401) {
					_tokens = null;
					return do_fetch(data);
				}
				return response;
			},
			error => {
				postMessage({ id: data.id, ok: false, data: { error: error } });
			}
		).catch(error => {
			postMessage({ id: data.id, ok: false, data: { error: error.message } });
		});
	});
}

function do_whoami(data) {
	tokens().then(tokens => {
		if (tokens.id) {
			const json = JSON.parse(base64url_decode(tokens.id.split('.')[1]));
			return postMessage({ id: data.id, ok: true, data: json });
		}
		config.then(config => {
			if (!config.openid.userinfo_endpoint)
				return postMessage({ id: data.id, ok: true, data: null });
			data.data = {
				uri: config.openid.userinfo_endpoint
			};
			_do_fetch(data).then(response => {
				return response.json();
			}).then(json => {
				postMessage({ id: data.id, ok: true, data: json });
			}).catch(error => {
				postMessage({ id: data.id, ok: false, data: { error: error.message } });
			});
		});
	});
}

function do_fetch(data) {
	let response = null;

	_do_fetch(data).then(response0 => {
		response = response0;
		return response0.text();
	}).then(body => {
		const headers = {};
		for (let pair of response.headers.entries())
			headers[pair[0].toLowerCase()] = pair[1];
		postMessage({ id: data.id, ok: true, data: {
			ok: response.ok,
			status: response.status,
			headers: headers,
			body: body
		}});
	});
}

onmessage = function(e) {
	const cb = function(){
		let dispatch = null;

		switch (e.data.type) {
		case 'init':
			dispatch = init;
			break;
		case 'whoami':
			dispatch = do_whoami;
			break;
		case 'fetch':
			dispatch = do_fetch;
			break;
		default:
			if (!(e.data.id in pending))
				return console.warn('orphan', e.data);
			const promise = pending[e.data.id];
			delete pending[e.data.id];
			dispatch = e.data.ok ? promise.resolve : promise.reject;
		}

		dispatch(e.data);
	};

//	console.info(e.data);

	if (config)
		config.then(cb)
	else if (e.data.type == 'init')
		cb()
	else
		throw new Error('uninit');
}

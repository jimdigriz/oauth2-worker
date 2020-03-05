class OAuth2 {
	constructor(config) {
		if (typeof config != 'object') throw new Error('missing configuration');
		if (!('client_id' in config)) throw new Error("missing 'client_id'");
		if (!('redirect_uri' in config)) throw new Error("missing 'redirect_uri'");
		if (!('discovery_endpoint' in config || 'authorization_endpoint' in config)) throw new Error("need either '{discovery,authorization}_endpoint'");
		if (typeof config.authorize_callback != 'function') throw new Error("missing 'callback' function");

		this.pending = {};

		this.callback = config.authorize_callback;
		delete config.authorize_callback;

		this.whoami = this._whoami.bind(this);
		this.fetch = this._fetch.bind(this);

		this.worker = new Worker('oauth2-worker.js');

		this.worker.onmessage = this.__recv.bind(this);

		this.worker.postMessage({ type: 'init', data: config });
	}

	_whoami() {
		return this.__send({ type: 'whoami' });
	}

	_fetch(uri, options) {
		if (options.headers) {
			Object.keys(options.headers).forEach((k) => {
				const v = options.headers[k];
				delete options.headers[k];
				options.headers[k.toLowerCase()] = v;
			});
		}
		if (options.body && !(options.headers && options.headers['content-type'])) {
			options.headers = options.headers || {};
			if (options.body instanceof URLSearchParams) {
				options.headers['content-type'] = 'application/x-www-form-urlencoded; charset=utf-8';
				options.body = options.body.toString();
			}
		}
		return this.__send({ type: 'fetch', data: { uri: uri, options: options } });
	}

	__authorize(data) {
		new Promise((resolve, reject) => {
			this.callback({ resolve: resolve, reject: reject });
		}).then((promise) => {
			return new Promise((resolve, reject) => {
				this.pending[data.id] = { resolve: resolve, reject: reject };

				const source = window.open(data.data.uri, '_blank');

				const cb = (e) => {
					if (e.source != source) return;

//					console.info(e);

					if (typeof e.data != 'object')
						return console.warn('orphan', e.data);

					if (e.data.id == data.id)
						this.worker.postMessage(e.data)
					else if (e.data.id == null) {
						console.warn('failed', e.data.data);
						reject(e.data.data);
					} else {
						console.error('mismatch', e.data);
						reject(e.data);
					}

					source.close();

					window.removeEventListener('message', cb);
				}

				window.addEventListener('message', cb);
			}).then(data => {
				promise.resolve({ ok: true });
			}).catch(error => {
				promise.reject({ ok: false, error: error });
			});
		});
	}

	__send(data) {
		// https://stackoverflow.com/a/2117523
		function uuidv4() {
			return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
				(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
			);
		}

		return new Promise((resolve, reject) => {
			data.id = uuidv4();

			this.pending[data.id] = { resolve: resolve, reject: reject };

			this.worker.postMessage(data);
		});
	}

	__recv(e) {
//		console.info(e.data);

		switch (e.data.type) {
		case 'authorize':
			this.__authorize(e.data);
			break;
		default:
			if (!(e.data.id in this.pending))
				return console.warn('orphan', e.data);
			const promise = this.pending[e.data.id];
			delete this.pending[e.data.id];
			if (e.data.ok)
				promise.resolve(e.data.data)
			else
				promise.reject(e.data.data);
		}
	}
}

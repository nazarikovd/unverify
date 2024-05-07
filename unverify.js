const frida = require('frida');
const express = require('express')
const fs = require('fs');



module.exports = class unverify{

	constructor(port){
		this.hook = fs.readFileSync('./hook.js', "utf-8")
		this.script = null
		this.session = null
		this.device = null
		this.pid = null
		this.readyhttp = null
		this.currentRequest = {
			"session_id": null,
			"phone": null,
			"external_id": null
		}
		this.dataToSend = null
		this.app = express()
		this.port = port
		this.package = 'com.vkontakte.android'
	}

	async init(){
		let self = this
		this.readyhttp = false

		try{
			this.device = await frida.getUsbDevice({ timeout: 15000 })
		}catch(e){
			this.updateState('Failed to find device ('+e+')', 1)
			return
		}
		
		try{
			this.pid = await this.device.spawn(this.package);
		}catch(e){
			this.updateState('Failed to spawn '+this.package+' ('+e+')', 1)
			return
		}
		
		try{
			this.session = await this.device.attach(this.pid);
		}catch(e){
			this.updateState('Failed to attach '+this.package+' ('+e+')', 1)
			return
		}
		
		try{
			this.script = await this.session.createScript(this.hook);
			this.session.detached.connect((reason, crash) => {
				self.stop(self, true, reason);
			})
		}catch(e){
			this.updateState('Failed to inject '+this.package+' ('+e+')', 1)
			return
		}
		
		this.initAPI(this.app)
		this.initScript()
	}

	async initAPI(){

		this.app.get('/', (req, res) => {

			if (!this.readyhttp) {
				res.send({
					"error": "libverify is not ready. Goto "+this.package+" and send registration request"
				})
				return
			}

			if (req.query.session_id) {
				this.currentRequest.session_id = req.query.session_id
			} else {
				res.send({
					"error": "session_id cant be empty"
				})
				return
			}
			if (req.query.phone) {
				this.currentRequest.phone = req.query.phone
			} else {
				res.send({
					"error": "phone cant be empty"
				})
				return
			}
			if (req.query.external_id) {
				this.currentRequest.external_id = req.query.external_id
			}

			if (this.script) {
				this.script.post({
					'type': 'data',
					'payload': {
						s: this.currentRequest.session_id,
						p: this.currentRequest.phone
					}
				})

				let inter = setInterval(() => {
					if (this.datatosend) {
						clearInterval(inter)
						let json = this.datatosend.json
						if (this.currentRequest.external_id) {
							json.external_id = this.currentRequest.external_id
						}
						let url = this.getUrlAndSign(json)
						this.cleanRequest()
						res.send({
							"success": true,
							"json": json,
							"url": url
						})
					}
				}, 100)

			} else {
				console.log('err: script not loaded?', 1)
			}
		})
		this.app.listen(this.port, () => {
  		})
	}

	async initScript(){
		this.script.message.connect(msg => {
			if (msg.payload) {
				switch (msg.payload.type) {
					case 'ready':
						this.readyhttp = true
						this.updateState('libverify is ready', 2)
						break;
					case 'request':
						let json = msg.payload.json
						this.datatosend = {
							"json": json,
						}
						break;
					default:
						console.log(msg)
						break
				}
			}
		})

		await this.script.load();
		await this.device.resume(this.pid);
		process.stdin.resume(); // keep process running
		let self = this
		process.on('SIGTERM', function(){
			self.stop(self)
		});
		process.on('SIGINT', function(){
			self.stop(self)
		});
		this.updateState('waiting for registration request...\ngo to '+this.package+' and send one', 3)
	}

	getUrlAndSign(data) {
		let MD5 = function(d) {
			var r = M(V(Y(X(d), 8 * d.length)));
			return r.toLowerCase()
		};

		function M(d) {
			for (var _, m = "0123456789ABCDEF", f = "", r = 0; r < d.length; r++) _ = d.charCodeAt(r), f += m.charAt(_ >>> 4 & 15) + m.charAt(15 & _);
			return f
		}

		function X(d) {
			for (var _ = Array(d.length >> 2), m = 0; m < _.length; m++) _[m] = 0;
			for (m = 0; m < 8 * d.length; m += 8) _[m >> 5] |= (255 & d.charCodeAt(m / 8)) << m % 32;
			return _
		}

		function V(d) {
			for (var _ = "", m = 0; m < 32 * d.length; m += 8) _ += String.fromCharCode(d[m >> 5] >>> m % 32 & 255);
			return _
		}

		function Y(d, _) {
			d[_ >> 5] |= 128 << _ % 32, d[14 + (_ + 64 >>> 9 << 4)] = _;
			for (var m = 1732584193, f = -271733879, r = -1732584194, i = 271733878, n = 0; n < d.length; n += 16) {
				var h = m,
					t = f,
					g = r,
					e = i;
				f = md5_ii(f = md5_ii(f = md5_ii(f = md5_ii(f = md5_hh(f = md5_hh(f = md5_hh(f = md5_hh(f = md5_gg(f = md5_gg(f = md5_gg(f = md5_gg(f = md5_ff(f = md5_ff(f = md5_ff(f = md5_ff(f, r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 0], 7, -680876936), f, r, d[n + 1], 12, -389564586), m, f, d[n + 2], 17, 606105819), i, m, d[n + 3], 22, -1044525330), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 4], 7, -176418897), f, r, d[n + 5], 12, 1200080426), m, f, d[n + 6], 17, -1473231341), i, m, d[n + 7], 22, -45705983), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 8], 7, 1770035416), f, r, d[n + 9], 12, -1958414417), m, f, d[n + 10], 17, -42063), i, m, d[n + 11], 22, -1990404162), r = md5_ff(r, i = md5_ff(i, m = md5_ff(m, f, r, i, d[n + 12], 7, 1804603682), f, r, d[n + 13], 12, -40341101), m, f, d[n + 14], 17, -1502002290), i, m, d[n + 15], 22, 1236535329), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 1], 5, -165796510), f, r, d[n + 6], 9, -1069501632), m, f, d[n + 11], 14, 643717713), i, m, d[n + 0], 20, -373897302), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 5], 5, -701558691), f, r, d[n + 10], 9, 38016083), m, f, d[n + 15], 14, -660478335), i, m, d[n + 4], 20, -405537848), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 9], 5, 568446438), f, r, d[n + 14], 9, -1019803690), m, f, d[n + 3], 14, -187363961), i, m, d[n + 8], 20, 1163531501), r = md5_gg(r, i = md5_gg(i, m = md5_gg(m, f, r, i, d[n + 13], 5, -1444681467), f, r, d[n + 2], 9, -51403784), m, f, d[n + 7], 14, 1735328473), i, m, d[n + 12], 20, -1926607734), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 5], 4, -378558), f, r, d[n + 8], 11, -2022574463), m, f, d[n + 11], 16, 1839030562), i, m, d[n + 14], 23, -35309556), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 1], 4, -1530992060), f, r, d[n + 4], 11, 1272893353), m, f, d[n + 7], 16, -155497632), i, m, d[n + 10], 23, -1094730640), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 13], 4, 681279174), f, r, d[n + 0], 11, -358537222), m, f, d[n + 3], 16, -722521979), i, m, d[n + 6], 23, 76029189), r = md5_hh(r, i = md5_hh(i, m = md5_hh(m, f, r, i, d[n + 9], 4, -640364487), f, r, d[n + 12], 11, -421815835), m, f, d[n + 15], 16, 530742520), i, m, d[n + 2], 23, -995338651), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 0], 6, -198630844), f, r, d[n + 7], 10, 1126891415), m, f, d[n + 14], 15, -1416354905), i, m, d[n + 5], 21, -57434055), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 12], 6, 1700485571), f, r, d[n + 3], 10, -1894986606), m, f, d[n + 10], 15, -1051523), i, m, d[n + 1], 21, -2054922799), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 8], 6, 1873313359), f, r, d[n + 15], 10, -30611744), m, f, d[n + 6], 15, -1560198380), i, m, d[n + 13], 21, 1309151649), r = md5_ii(r, i = md5_ii(i, m = md5_ii(m, f, r, i, d[n + 4], 6, -145523070), f, r, d[n + 11], 10, -1120210379), m, f, d[n + 2], 15, 718787259), i, m, d[n + 9], 21, -343485551), m = safe_add(m, h), f = safe_add(f, t), r = safe_add(r, g), i = safe_add(i, e)
			}
			return Array(m, f, r, i)
		}

		function md5_cmn(d, _, m, f, r, i) {
			return safe_add(bit_rol(safe_add(safe_add(_, d), safe_add(f, i)), r), m)
		}

		function md5_ff(d, _, m, f, r, i, n) {
			return md5_cmn(_ & m | ~_ & f, d, _, r, i, n)
		}

		function md5_gg(d, _, m, f, r, i, n) {
			return md5_cmn(_ & f | m & ~f, d, _, r, i, n)
		}

		function md5_hh(d, _, m, f, r, i, n) {
			return md5_cmn(_ ^ m ^ f, d, _, r, i, n)
		}

		function md5_ii(d, _, m, f, r, i, n) {
			return md5_cmn(m ^ (_ | ~f), d, _, r, i, n)
		}

		function safe_add(d, _) {
			var m = (65535 & d) + (65535 & _);
			return (d >> 16) + (_ >> 16) + (m >> 16) << 16 | 65535 & m
		}

		function bit_rol(d, _) {
			return d << _ | d >>> 32 - _
		}
		let newdata = {}
		Object.keys(data).sort().forEach(function(v, i) {
			newdata[v] = data[v]
		});
		let p = new URLSearchParams(newdata).toString();
		let pars
		pars = p.replace(/&/g, "");
		pars = pars.replace(/=/g, "");
		let method = "verify"
		let next = method + pars + '506e786f377863526a7558536c644968'
		let sign = MD5(next)
		return 'https://clientapi.mail.ru/fcgi-bin/' + method + '?' + p + '&signature=' + sign
	}

	cleanRequest(){
		this.currentRequest = {
			"session_id": null,
			"phone": null,
			"external_id": null
		}
		this.datatosend - null
	}

	stop(self, detached = false, reason = null) {
	    if (self.script !== null) {
	        self.script.unload().then(() => {
	        	self.script = null;
	        	self.updateState('[!] script unloaded', 3);
	        	self.session.detach();
	        	self.updateState('[!] session stop', 3);
	        	process.exit(1);
	        }).catch(console.error);
	    }else{
	    	self.updateState('[!] unexpected unload', 2);
	    }
	    if(detached){
	    	self.updateState('[!] session disconnected '+reason, 3);
	       	process.exit(1);
	    }
	}

	updateState(state, color=0){
		console.clear()
		console.log(`http://localhost:${this.port}`)
		switch(color){
			case 0:
				console.log('status: '+state)
				break;
			case 1:
				console.log('status: \x1b[31m'+state+'\x1b[0m')
				break;
			case 2:
				console.log('status: \x1b[32m'+state+'\x1b[0m')
				break;
			default:
				console.log('status: \x1b[33m'+state+'\x1b[0m')
		}
	}


}





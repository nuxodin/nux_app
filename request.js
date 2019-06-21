import { delCookie, setCookie, getCookies } from "https://deno.land/std/http/cookie.ts";
//import Introspected from "https://raw.githubusercontent.com/nuxodin/introspected/master/esm/introspected.js";

export class Request {
	constructor(req){
		this.url = req.url;
		this.request = req;
		this.response = {
			header:{},
			csp: {
				'child-src' : {},
				'connect-src' : {},
				'default-src' : {},
				'font-src' : {},
				'frame-src' : {},
				'img-src' : {},
				'manifest-src' : {},
				'media-src' : {},
				'object-src' : {},
				'prefetch-src' : {},
				'script-src' : {},
				'script-src-elem' : {},
				'script-src-attr' : {},
				'style-src' : {},
				'style-src-elem' : {},
				'style-src-attr' : {},
				'worker-src' : {},
			},
			csp_report: {
				'child-src' : {},
				'connect-src' : {},
				'default-src' : {},
				'font-src' : {},
				'frame-src' : {},
				'img-src' : {},
				'manifest-src' : {},
				'media-src' : {},
				'object-src' : {},
				'prefetch-src' : {},
				'script-src' : {},
				'script-src-elem' : {},
				'script-src-attr' : {},
				'style-src' : {},
				'style-src-elem' : {},
				'style-src-attr' : {},
				'worker-src' : {},
			},
		};
		this.cookie = new nuxCookies(this.request);
	}
	respond(obj){
		this.response.header['Content-Security-Policy-Report-Only'] = generateCsp(this.response.csp_report);
		this.response.header['Content-Security-Policy'] = generateCsp(this.response.csp);
		const headers = new Headers();
		for (const key in this.response.header) {
			headers.set(key, this.response.header[key]);
		}

		// mixin argument
		if (obj.status !== undefined) this.response.status = obj.status;
		if (obj.body !== undefined) this.response.body = obj.body;
		if (obj.headers) {
			for (let h of obj.headers) { // will it add multiple same headers?
				headers.set(h[0], h[1]);
			}
		}

		const response = {
			status: this.response.status,
			body: this.response.body,
			headers
		};

		this.cookie.toResponse(response);
		if (typeof response.body === 'string') response.body = new TextEncoder().encode(response.body);
		this.request.respond(response);

		this.sessionObject.save();
	}
	async initSession(){
		this.sessionObject = new Session(this);
		await this.sessionObject.init();
		this.sess = this.sessionObject.data;
	}
}


class nuxCookies {
	constructor(request){
		this.request = request;
		this.newCookies = Object.create(null);
	}
	get oldCookies(){
		var cookies = getCookies(this.request);
		Object.defineProperty(this,'oldCookies',{value:cookies});
		return cookies;
	}
	get(name){
		return this.newCookies[name]!==undefined ? this.newCookies[name].value : this.oldCookies[name];
	}
	set(name, options){
		if (typeof options === 'number') options = options+'';
		if (typeof options === 'string') options = {value:options};
		if (options.value === undefined) console.warn('no cookie value!');
		options.name = name;
		this.newCookies[name] = options;
	}
	delete(name){
		//if (this.oldCookies[name]) { // only if cookie was sent
			this.newCookies[name] = undefined;
		//}
		this.oldCookies[name] = undefined;
	}
	toResponse(response) {
		for (const name in this.newCookies) {
			const cookie = this.newCookies[name];
			if (cookie === undefined) {
				delCookie(response, name);
			} else {
				setCookie(response, cookie);
			}
		}
	}
}





class Session {
	constructor(request){
		this.store = SessionStoreMemory;
		this.request = request;
	}
	async init() {
		let reportedId = this.request.cookie.get('sess');
		if (!reportedId) {
			await this._create();
		} else {
			this.data = await this.store.getData(reportedId);
			if (this.data) {
				this.id = reportedId;
			} else { // session not found on server
				await this._create();
			}
		}
		this.oldJsonString = JSON.stringify(this.data);
	}
	async _create(){
		this.id = Math.random();
		this.request.cookie.set('sess', this.id);
		this.data = await this.store.createData(this.id);
	}
	async save() {
		const newJsonString = JSON.stringify(this.data);
		var changed = this.oldJsonString !== newJsonString;
		if (changed) this.store.saveData(this.id, this.data);
	}
}


const SessionStoreMemory = {
	async createData(id){
		const sess = this.allSessions[id] = {
			created: Date.now(),
			lastAccess: Date.now(),
			data:{}
		};
		return sess.data;
	},
	async getData(id){
		if (!this.allSessions[id]) return false;
		this.allSessions[id].lastAccess = Date.now();
		return this.allSessions[id].data;
	},
	async saveData(id, data) {
		this.allSessions[id].data = data;
	},
	allSessions:{}
};



function generateCsp(csp) {
	if (csp['default-src']["'none'"] && Object.entries(csp['default-src']).length > 1) delete csp['default-src']["'none'"];
	let str = '';
	for (const type in csp) {
		let allowed = csp[type];
		allowed = Object.entries(allowed).filter(entry=>entry[1]);
		if (!allowed.length) continue;
		str += type+' '+allowed.map(item=>item[0]).join(' ')+'; ';
	}
	if (csp.report_uri) str += ' report-uri '.csp.report_uri;
	return str;
}

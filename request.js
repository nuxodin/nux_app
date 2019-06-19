import { delCookie, setCookie, getCookies } from "https://deno.land/std/http/cookie.ts";

export class NuxRequest {
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
		this.request.respond(response);
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
		this.request = request;
		let id = this.request.cookie.get('sess');
		if (!id) {
			id = Math.random();
			this.request.cookie.set('sess', id);
		}
		this.getData();
	}
}
class SessionData {

}



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

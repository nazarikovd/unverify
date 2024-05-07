let hContext;
let hCContext;
let hApiManager;
let hFunction;
let Hsystem_id;
let Happ_id;
let Hready = false;

Java.perform(() => {
	let m = Java.use("ru.mail.libverify.storage.m");
	m["a"].implementation = function(context, commonContext, apiManager, str, str2) {
		hContext = Java.retain(context)
		hCContext = Java.retain(commonContext)
		hApiManager = Java.retain(apiManager)
		hFunction = Java.retain(this)
		let result = this["a"](context, commonContext, apiManager, str, str2);
		if (!Hready) {
			send({
				"type": "ready"
			})
			Hready = true
		}
		return result;
	};
	let RequestBase = Java.use("ru.mail.verify.core.requests.RequestBase");
	RequestBase["addUrlParam"].implementation = function(sb, entry) {
		if (sb.toString().includes('system_id')) {
			Hsystem_id = sb.toString().split('system_id=')[1].toString().split('&')[0]
		}
		if (sb.toString().includes('application_id')) {
			Happ_id = sb.toString().split('application_id=')[1].toString().split('&')[0]
		}
		this["addUrlParam"](sb, entry);
	};
})
recv('data', onData);

function onData(value) {
	let data = value.payload;
	let result = hFunction["a"](hContext, hCContext, hApiManager, data.s, data.p);
	let ret = {
		"application": "VK",
		"application_id": Happ_id,
		"capabilities": "sms_retriever",
		"checks": "sms",
		"libverify_build": "257",
		"libverify_version": "2.9.1",
		"phone": data.p,
		"platform": "android",
		"request_id": result,
		"service": "vk_registration",
		"session_id": data.s,
		"system_id": Hsystem_id,
	}
	send({
		"type": "request",
		"json": ret
	})
	recv('data', onData);
}
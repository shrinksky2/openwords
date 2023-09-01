// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd8940f50-d7b6-405e-b016-3e5052b4c884';

let proxyIP = '';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/':
						return new Response(JSON.stringify(request.cf), { status: 200 });
					case `/${userID}`: {
						const vmessConfig = getVMessConfig(userID, request.headers.get('Host'));
						return new Response(`${vmessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					default:
						return new Response('Not found', { status: 404 });
				}
			} else {
				return await vmessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * 
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vmessOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vmessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVMessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '
				} `;
			if (hasError) {
				throw new Error(message);
				return;
			}
			// if UDP but port not DNS port, close it
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP proxy only enable for DNS which is port 53');
					return;
				}
			}
			const vmessResponseHeader = new Uint8Array([vmessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			// TODO: support udp here when cf runtime has udp support
			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vmessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vmessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vmessResponseHeader The VMess response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vmessResponseHeader, log) {
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); 
		writer.releaseLock();
		return tcpSocket;
	}

	// if the cf connect tcp socket have no incoming data, we retry to redirect ip
	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vmessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vmessResponseHeader, retry, log);
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(string)=> void} log 
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			}
			);

			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
		},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

/**
 * 
 * @param {ArrayBuffer} vmessBuffer 
 * @param {string} userID 
 * @returns 
 */
function processVMessHeader(
	vmessBuffer,
	userID
) {
	if (vmessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(vmessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify(new Uint8Array(vmessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vmessBuffer.slice(17, 18))[0];

	const command = new Uint8Array(
		vmessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vmessBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vmessBuffer.slice(addressIndex, addressIndex + 1)
	);

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vmessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vmessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vmessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vmessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
				message: `invalid addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vmessVersion: version,
		isUDP,
	};
}

/**
 * 
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vmessResponseHeader The VMess response header.
 * @param {(string)=> void} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vmessResponseHeader, log) {
	async function connectAndWrite(address, port) {
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vmessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	remoteSocketToWS(tcpSocket, webSocket, vmessResponseHeader, retry, log);
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader for ws 0rtt
 * @param {(string)=> void} log 
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			}
			);

			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
		},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

/**
 * 
 * @param {string} base64Str 
 * @returns 
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * This is not real UUID validation
 * @param {string} uuid 
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

/**
 * Normally, WebSocket will not have exceptions when close.
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} vmessResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleUDPOutBound(webSocket, vmessResponseHeader, log) {

	let isVMessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const packetLength = new DataView(lengthBuffer).getUint16(0);
				index += 2;
				const packet = chunk.slice(index, index + packetLength);
				index += packetLength;
				const buffer = new Uint8Array(vmessResponseHeader.length + packet.length);
				buffer.set(vmessResponseHeader, 0);
				buffer.set(new Uint8Array(packet), vmessResponseHeader.length);
				controller.enqueue(buffer);
			}
		}
	});
	let isWritePending = false;
	const writer = webSocket.writable.getWriter();

	const stream = new WritableStream({
		async write(chunk, controller) {
			const lengthBuffer = chunk.slice(0, 2);
			const packetLength = new DataView(lengthBuffer).getUint16(0);
			const packet = chunk.slice(2, 2 + packetLength);
			const writerResult = writer.write(packet);
			if (!isVMessHeaderSent) {
				isVMessHeaderSent = true;
				isWritePending = true;
				writerResult.finally(() => {
					isWritePending = false;
				})
				log('UDP VMess header sent');
			}
		},
		close() {
			log(`UDP Write stream is closed`);
		},
		abort(reason) {
			log(`UDP Write stream is aborted`, JSON.stringify(reason));
		},
	});

	return {
		write(chunk) {
			if (isVMessHeaderSent) {
				return stream.write(chunk);
			} else {
				if (isWritePending) {
					return new Promise((resolve, reject) => {
						writer.ready.then(() => {
							if (stream.state === 'writable') {
								stream.write(chunk).then(resolve).catch(reject);
							} else {
								resolve();
							}
						}).catch(reject);
					})
				} else {
					const lengthBuffer = chunk.slice(0, 2);
					const packetLength = new DataView(lengthBuffer).getUint16(0);
					const packet = chunk.slice(2, 2 + packetLength);
					const writerResult = writer.write(packet);
					isVMessHeaderSent = true;
					log('UDP VMess header sent');
					return writerResult.then(() => { });
				}
			}
		},
	};
}

/**
 * 
 * @param {import("@cloudflare/workers-types").Socket} tcpSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {Uint8Array} vmessResponseHeader 
 * @param {function} retry
 * @param {(string)=> void} log 
 */
async function remoteSocketToWS(tcpSocket, webSocket, vmessResponseHeader, retry, log) {
	const reader = tcpSocket.readable.getReader();
	let isVMessHeaderSent = false;
	const writer = webSocket.writable.getWriter();

	// This keeps track of whether a retry is pending.
	// If a retry is pending, we shouldn't close the WebSocket.
	let isRetryPending = false;

	const handleTcpClosed = () => {
		// This function is called when the TCP socket is closed.
		// It will close the WebSocket if there are no retry attempts pending.
		if (!isRetryPending) {
			safeCloseWebSocket(webSocket);
		}
	};

	tcpSocket.closed.then(() => {
		// This will be called when the TCP socket is closed, either by the server or due to an error.
		log('TCP socket closed');
		handleTcpClosed();
	}).catch(error => {
		// Handle any errors that occur.
		console.error('TCP socket error', error);
		handleTcpClosed();
	});

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {
				break;
			}
			if (!isVMessHeaderSent) {
				// Send the VMess response header to the WebSocket client.
				isVMessHeaderSent = true;
				await writer.write(vmessResponseHeader);
			}
			await writer.write(value);
		}
	} catch (error) {
		console.error('TCP socket read error', error);
		if (retry) {
			// If a retry function is provided, attempt to retry the connection.
			isRetryPending = true;
			await retry();
		} else {
			// If no retry function is provided, close the WebSocket.
			safeCloseWebSocket(webSocket);
		}
	} finally {
		await writer.close();
		reader.releaseLock();
	}
}

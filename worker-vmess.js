// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';
// import { connectdb } from '@planetscale/database';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'f73f2359-ee43-423b-8e5d-232e351513fb';

const proxyIPs = ['cdn-all.xn--b6gac.eu.org', 'cdn.xn--b6gac.eu.org', 'cdn-b100.xn--b6gac.eu.org', 'edgetunnel.anycast.eu.org', 'cdn.anycast.eu.org'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

// v2board api environment variables (optional)
// now deprecated, please use planetscale.com instead
let nodeId = ''; // 1

let apiToken = ''; //abcdefghijklmnopqrstuvwxyz123456

let apiHost = ''; // api.v2board.com

if (!isValidUUID(userID)) {
    throw new Error('uuid is invalid');
}

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            nodeId = env.NODE_ID || nodeId;
            apiToken = env.API_TOKEN || apiToken;
            apiHost = env.API_HOST || apiHost;
            let userID_Path = userID;
            if (userID.includes(',')) {
                userID_Path = userID.split(',')[0];
            }
            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                const url = new URL(request.url);
                switch (url.pathname) {
                    case '/cf':
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            },
                        });
                    case '/connect': // for test connect to cf socket
                        const [hostname, port] = ['cloudflare.com', '80'];
                        console.log(`Connecting to ${hostname}:${port}...`);

                        try {
                            const socket = await connect({
                                hostname: hostname,
                                port: parseInt(port, 10),
                            });

                            const writer = socket.writable.getWriter();

                            try {
                                await writer.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n'));
                            } catch (writeError) {
                                writer.releaseLock();
                                await socket.close();
                                return new Response(writeError.message, { status: 500 });
                            }

                            writer.releaseLock();

                            const reader = socket.readable.getReader();
                            let value;

                            try {
                                const result = await reader.read();
                                value = result.value;
                            } catch (readError) {
                                await reader.releaseLock();
                                await socket.close();
                                return new Response(readError.message, { status: 500 });
                            }

                            await reader.releaseLock();
                            await socket.close();

                            return new Response(new TextDecoder().decode(value), { status: 200 });
                        } catch (connectError) {
                            return new Response(connectError.message, { status: 500 });
                        }
                    case `/${userID_Path}`: {
                        const vmessConfig = getVMessConfig(userID, request.headers.get('Host'));
                        return new Response(`${vmessConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            }
                        });
                    }
                    case `/sub/${userID_Path}`: {
                        const url = new URL(request.url);
                        const searchParams = url.searchParams;
                        let vmessConfig = createVMessSub(userID, request.headers.get('Host'));

                        // If 'format' query param equals to 'clash', convert config to base64
                        if (searchParams.get('format') === 'clash') {
                            vmessConfig = btoa(vmessConfig);
                        }

                        // Construct and return response object
                        return new Response(vmessConfig, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                    default:
                        // return new Response('Not found', { status: 404 });
                        // For any other path, reverse proxy to 'www.fmprc.gov.cn' and return the original response, caching it in the process
                        const hostnames = ['www.fmprc.gov.cn', 'www.xuexi.cn', 'www.gov.cn', 'mail.gov.cn', 'www.mofcom.gov.cn', 'www.gfbzb.gov.cn', 'www.miit.gov.cn', 'www.12377.cn'];
                        url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
                        url.protocol = 'https:';
                        const newHeaders = new Headers(request.headers);
                        newHeaders.set('cf-connecting-ip', newHeaders.get('x-forwarded-for') || newHeaders.get('cf-connecting-ip'));
                        newHeaders.set('x-forwarded-for', newHeaders.get('cf-connecting-ip'));
                        newHeaders.set('x-real-ip', newHeaders.get('cf-connecting-ip'));
                        newHeaders.set('x-forwarded-proto', newHeaders.get('x-forwarded-proto') || 'https');
                        request = new Request(url, {
                            method: request.method,
                            headers: newHeaders,
                            body: request.body,
                            redirect: request.redirect,
                        });
                        const cache = caches.default;
                        let response = await cache.match(request);
                        if (!response) {
                            // if not in cache, get response from origin
                            // send client ip to origin server to get right ip
                            try {
                                response = await fetch(request, { redirect: "manual" });
                            } catch (err) {
                                url.protocol = 'http:';
                                url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
                                request = new Request(url, {
                                    method: request.method,
                                    headers: newHeaders,
                                    body: request.body,
                                    redirect: request.redirect,
                                });
                                response = await fetch(request, { redirect: "manual" });
                            }
                            const cloneResponse = response.clone();
                            ctx.waitUntil(cache.put(request, cloneResponse));
                        }
                        return response;
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
 * Creates a PlanetScale connection object and returns it.
 * @param {{DATABASE_HOST: string, DATABASE_USERNAME: string, DATABASE_PASSWORD: string}} env The environment variables containing the database connection information.
 * @returns {Promise<object>} A Promise that resolves to the PlanetScale connection object.
 */
function getPlanetScaleConnection(env) {
    const config = {
        host: env.DATABASE_HOST,
        username: env.DATABASE_USERNAME,
        password: env.DATABASE_PASSWORD,
        fetch: (url, init) => {
            delete (init)["cache"];
            return fetch(url, init);
        }
    }
    return connectdb(config)
}

/**
 * Handles VMess over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VMess header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vmessOverWSHandler(request) {
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
            portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
            if (hasError) {
                // controller.error(message);
                throw new Error(message); // cf seems has bug, controller.error will not end stream
                // webSocket.close(1000, message);
                return;
            }

            // If UDP and not DNS port, close it
            if (isUDP && portRemote !== 53) {
                throw new Error('UDP proxy only enabled for DNS which is port 53');
                // cf seems has bug, controller.error will not end stream
            }

            if (isUDP && portRemote === 53) {
                isDns = true;
            }

            // ["version", "附加信息长度 N"]
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
        webSocket: client,
    });
}

let apiResponseCache = null;
let cacheTimeout = null;

/**
 * Fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the API response object or null if there was an error.
 */
async function fetchApiResponse() {
    const requestOptions = {
        method: 'GET',
        redirect: 'follow'
    };

    try {
        const response = await fetch(`https://${apiHost}/api/v1/server/UniProxy/user?node_id=${nodeId}&node_type=v2ray&token=${apiToken}`, requestOptions);

        if (!response.ok) {
            console.error('Error: Network response was not ok');
            return null;
        }
        const apiResponse = await response.json();
        apiResponseCache = apiResponse;

        // Refresh the cache every 5 minutes (300000 milliseconds)
        if (cacheTimeout) {
            clearTimeout(cacheTimeout);
        }
        cacheTimeout = setTimeout(() => fetchApiResponse(), 300000);

        return apiResponse;
    } catch (error) {
        console.error('Error:', error);
        return null;
    }
}

/**
 * Returns the cached API response if it exists, otherwise fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the cached API response object or the fetched API response object, or null if there was an error.
 */
async function getApiResponse() {
    if (!apiResponseCache) {
        return await fetchApiResponse();
    }
    return apiResponseCache;
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
    // Check if any of the environment variables are empty
    if (!nodeId || !apiToken || !apiHost) {
        return false;
    }

    try {
        const apiResponse = await getApiResponse();
        if (!apiResponse) {
            return false;
        }
        const isUuidInResponse = apiResponse.users.some(user => user.uuid === targetUuid);
        return isUuidInResponse;
    } catch (error) {
        console.error('Error:', error);
        return false;
    }
}

// Usage example:
//   const targetUuid = "65590e04-a94c-4c59-a1f2-571bce925aad";
//   checkUuidInApiResponse(targetUuid).then(result => console.log(result));

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
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vmessResponseHeader, log,) {

    /**
     * Connects to a given address and port and writes data to the socket.
     * @param {string} address The address to connect to.
     * @param {number} port The port to connect to.
     * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
     */
    async function connectAndWrite(address, port) {
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }

    /**
     * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
     * @returns {Promise<void>} A Promise that resolves when the retry is complete.
     */
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
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                const message = event.data;
                controller.enqueue(message);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });

            webSocketServer.addEventListener('error', (err) => {
                log('webSocketServer has error');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        cancel(reason) {
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/vmess.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the VMess header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vmessBuffer The VMess header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VMess header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vmessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VMess header buffer.
 */
function processVMessHeader(vmessBuffer, userID) {
    if (vmessBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }
    const version = new Uint8Array(vmessBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;
    const slicedBuffer = new Uint8Array(vmessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    // check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
    const uuids = userID.includes(',') ? userID.split(",") : [userID];
    console.log(slicedBufferString, uuids);

    // isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
    isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

    console.log(`userID: ${slicedBufferString}`);

    if (!isValidUser) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }

    const optLength = new Uint8Array(vmessBuffer.slice(17, 18))[0];
    //skip opt for now

    const command = new Uint8Array(
        vmessBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
        isUDP = false;
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `invalid cmd ${command}`,
        };
    }

    const addressType = new Uint8Array(
        vmessBuffer.slice(19 + optLength, 19 + optLength + 1)
    )[0];

    if (addressType === 0x01) {
        // IPv4 address
        const addressBuffer = new Uint8Array(
            vmessBuffer.slice(20 + optLength, 24 + optLength)
        );
        const portBuffer = new Uint8Array(
            vmessBuffer.slice(24 + optLength, 26 + optLength)
        );
        const addressRemote = Array.from(addressBuffer)
            .map((byte) => byte.toString())
            .join('.');
        const portRemote = (portBuffer[0] << 8) + portBuffer[1];

        return {
            hasError: false,
            addressRemote,
            addressType,
            portRemote,
            rawDataIndex: 26 + optLength,
            vmessVersion: version,
            isUDP,
        };
    } else if (addressType === 0x03) {
        // Domain name
        const domainLength = new Uint8Array(
            vmessBuffer.slice(20 + optLength, 21 + optLength)
        )[0];
        const domainBuffer = new Uint8Array(
            vmessBuffer.slice(21 + optLength, 21 + optLength + domainLength)
        );
        const portBuffer = new Uint8Array(
            vmessBuffer.slice(21 + optLength + domainLength, 23 + optLength + domainLength)
        );
        const addressRemote = Array.from(domainBuffer)
            .map((byte) => String.fromCharCode(byte))
            .join('');
        const portRemote = (portBuffer[0] << 8) + portBuffer[1];

        return {
            hasError: false,
            addressRemote,
            addressType,
            portRemote,
            rawDataIndex: 23 + optLength + domainLength,
            vmessVersion: version,
            isUDP,
        };
    } else if (addressType === 0x04) {
        // IPv6 address (not supported)
        return {
            hasError: true,
            message: 'IPv6 address not supported',
        };
    } else {
        return {
            hasError: true,
            message: `invalid address type ${addressType}`,
        };
    }
}

/**
 * Handles UDP outbound connections by creating a UDP socket and setting up data listeners.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the UDP socket to.
 * @param {Uint8Array} vmessResponseHeader The VMess response header.
 * @param {function} log The logging function.
 * @returns {{
 *   write: function(Uint8Array): void,
 *   close: function(): Promise<void>,
 * }} An object with write and close methods to handle UDP connections.
 */
async function handleUDPOutBound(webSocket, vmessResponseHeader, log) {
    const udpSocket = new UDPSocket();
    await udpSocket.bind();

    /**
     * Writes data to the UDP socket.
     * @param {Uint8Array} data The data to write to the UDP socket.
     */
    function write(data) {
        try {
            udpSocket.send(data);
        } catch (error) {
            log(`UDP socket send error: ${error.message}`);
        }
    }

    /**
     * Closes the UDP socket.
     */
    async function close() {
        try {
            await udpSocket.close();
        } catch (error) {
            log(`UDP socket close error: ${error.message}`);
        }
        safeCloseWebSocket(webSocket);
    }

    udpSocket.addEventListener('message', (event) => {
        const message = event.data;
        webSocket.send(vmessResponseHeader);
        webSocket.send(message);
    });

    udpSocket.addEventListener('error', (event) => {
        log(`UDP socket error: ${event.error}`);
        close();
    });

    return {
        write,
        close,
    };
}

/**
 * Passes data between a WebSocket and a remote socket.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to pass data to.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass data from.
 * @param {Uint8Array} vmessResponseHeader The VMess response header.
 * @param {function} retryCallback The callback to call when a retry is needed (only for UDP).
 * @param {function} log The logging function.
 */
function remoteSocketToWS(remoteSocket, webSocket, vmessResponseHeader, retryCallback, log) {
    const readableRemoteSocketStream = makeReadableSocketStream(remoteSocket, log);

    readableRemoteSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (retryCallback) {
                retryCallback();
            }
            if (!webSocket.readyState === WebSocket.OPEN) {
                log(`WebSocket is not open`);
                controller.error('WebSocket is not open');
                return;
            }
            try {
                webSocket.send(vmessResponseHeader);
                webSocket.send(chunk);
            } catch (error) {
                log(`WebSocket send error: ${error.message}`);
                controller.error(`WebSocket send error: ${error.message}`);
                return;
            }
        },
        close() {
            log(`remoteSocketToWS is close`);
        },
        abort(reason) {
            log(`remoteSocketToWS is abort`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log('remoteSocketToWS pipeTo error', err);
    });

    webSocket.addEventListener('message', (event) => {
        const message = event.data;
        remoteSocket.send(message);
    });

    webSocket.addEventListener('close', () => {
        safeCloseSocket(remoteSocket, log);
    });

    webSocket.addEventListener('error', (event) => {
        log(`WebSocket error: ${event.error}`);
        safeCloseSocket(remoteSocket, log);
    });
}

/**
 * Creates a readable stream from a remote socket, allowing for data to be read from the socket.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to create the readable stream from.
 * @param {function} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the remote socket.
 */
function makeReadableSocketStream(remoteSocket, log) {
    let readableStreamCancel = false;

    const stream = new ReadableStream({
        start(controller) {
            remoteSocket.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            remoteSocket.addEventListener('close', () => {
                if (readableStreamCancel) {
                    return;
                }
                log(`remoteSocket is close`);
                controller.close();
            });

            remoteSocket.addEventListener('error', (err) => {
                if (readableStreamCancel) {
                    return;
                }
                log(`remoteSocket has error`);
                controller.error(err);
            });
        },

        pull(controller) {
            // if remoteSocket can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        cancel(reason) {
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            safeCloseSocket(remoteSocket, log);
        }
    });

    return stream;
}

/**
 * Safely closes a WebSocket and logs any errors.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to close.
 */
function safeCloseWebSocket(webSocket) {
    try {
        webSocket.close();
    } catch (error) {
        console.error('WebSocket close error:', error);
    }
}

/**
 * Safely closes a remote socket and logs any errors.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to close.
 * @param {function} log The logging function.
 */
function safeCloseSocket(remoteSocket, log) {
    try {
        remoteSocket.close();
    } catch (error) {
        log('remoteSocket close error:', error);
    }
}

/**
 * Converts a base64-encoded string to an ArrayBuffer.
 * @param {string} base64String The base64-encoded string to convert.
 * @returns {{data: ArrayBuffer, error: null} | {data: null, error: Error}} An object with the data ArrayBuffer or an error if the conversion fails.
 */
function base64ToArrayBuffer(base64String) {
    try {
        const binaryString = atob(base64String);
        const length = binaryString.length;
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { data: bytes.buffer, error: null };
    } catch (error) {
        return { data: null, error: error };
    }
}

/**
 * Converts a Uint8Array to a string.
 * @param {Uint8Array} array The Uint8Array to convert to a string.
 * @returns {string} The converted string.
 */
function stringify(array) {
    let str = '';
    for (let i = 0; i < array.length; i++) {
        str += String.fromCharCode(array[i]);
    }
    return str;
}

/**
 * Entry point for the Cloudflare worker.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @param {Object} env The environment variables for the worker.
 * @returns {Promise<Response>} A Promise that resolves to the response object.
 */
addEventListener('fetch', (event) => {
    event.respondWith(handleRequest(event.request, {
        DATABASE_HOST: "your-database-host",
        DATABASE_USERNAME: "your-database-username",
        DATABASE_PASSWORD: "your-database-password",
    }));
});

/**
 * Checks if the request method is allowed.
 * @param {string} method The request method to check.
 * @returns {boolean} True if the method is allowed, false otherwise.
 */
function isMethodAllowed(method) {
    return method === 'GET' || method === 'POST';
}

/**
 * Handles incoming HTTP requests.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @param {object} env The environment variables for the worker.
 * @returns {Promise<Response>} A Promise that resolves to the response object.
 */
async function handleRequest(request, env) {
    // Check if the request method is allowed
    if (!isMethodAllowed(request.method)) {
        return new Response('Method Not Allowed', { status: 405 });
    }

    // Get the request URL and pathname
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Handle API requests
    if (pathname.startsWith('/api')) {
        return handleApiRequest(request, pathname, env);
    }

    // Handle WebSocket requests
    if (request.headers.get('Upgrade') === 'websocket') {
        return handleWebSocket(request, env);
    }

    // Default response for other requests
    return new Response('Not Found', { status: 404 });
}

/**
 * Handles API requests.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @param {string} pathname The pathname of the API request.
 * @param {object} env The environment variables for the worker.
 * @returns {Promise<Response>} A Promise that resolves to the API response.
 */
async function handleApiRequest(request, pathname, env) {
    // Check if the request is for the user API
    if (pathname.startsWith('/api/v1/server/UniProxy/user')) {
        // Parse the query parameters
        const params = new URL(request.url).searchParams;
        const nodeId = params.get('node_id');
        const nodeType = params.get('node_type');
        const token = params.get('token');

        // Check if any of the parameters are missing
        if (!nodeId || !nodeType || !token) {
            return new Response('Bad Request', { status: 400 });
        }

        // Check if the node type is "v2ray"
        if (nodeType !== 'v2ray') {
            return new Response('Not Found', { status: 404 });
        }

        // Check if the token is correct
        if (token !== env.API_TOKEN) {
            return new Response('Unauthorized', { status: 401 });
        }

        // Check if the node ID is valid
        if (!isValidNodeId(nodeId)) {
            return new Response('Not Found', { status: 404 });
        }

        // Fetch the user data from the database
        const user = await getUserData(nodeId, env);

        // Check if the user data was found
        if (!user) {
            return new Response('Not Found', { status: 404 });
        }

        // Return the user data as JSON
        return new Response(JSON.stringify(user), {
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    // Default response for other API requests
    return new Response('Not Found', { status: 404 });
}

/**
 * Checks if a node ID is valid.
 * @param {string} nodeId The node ID to check.
 * @returns {boolean} True if the node ID is valid, false otherwise.
 */
function isValidNodeId(nodeId) {
    // Check if the node ID is a valid UUID
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    return uuidRegex.test(nodeId);
}

/**
 * Fetches user data from the database based on the node ID.
 * @param {string} nodeId The node ID to use as a lookup key.
 * @param {object} env The environment variables for the worker.
 * @returns {Promise<object|null>} A Promise that resolves to the user data object or null if the data was not found.
 */
async function getUserData(nodeId, env) {
    // Connect to the database
    const connection = await getPlanetScaleConnection(env);

    // Fetch the user data based on the node ID
    const query = `SELECT * FROM users WHERE node_id = ?`;
    const [rows] = await connection.execute(query, [nodeId]);

    // Close the database connection
    await connection.end();

    // Check if any rows were returned
    if (rows.length > 0) {
        return rows[0];
    } else {
        return null;
    }
}

/**
 * Connects to the PlanetScale database using the provided environment variables.
 * @param {object} env The environment variables for the worker.
 * @returns {Promise<import("mysql2/promise").Connection>} A Promise that resolves to the database connection.
 */
async function getPlanetScaleConnection(env) {
    const mysql = require('mysql2/promise');

    // Create a connection to the PlanetScale database
    const connection = await mysql.createConnection({
        host: env.DATABASE_HOST,
        user: env.DATABASE_USERNAME,
        password: env.DATABASE_PASSWORD,
        database: 'uni_proxy',
        ssl: {
            rejectUnauthorized: false,
        },
    });

    return connection;
}

/**
 * Handles WebSocket requests.
 * @param {import("@cloudflare/workers-types").Request} request The incoming WebSocket request.
 * @param {object} env The environment variables for the worker.
 * @returns {Response} The WebSocket response.
 */
function handleWebSocket(request, env) {
    // Upgrade the request to a WebSocket
    const webSocket = new WebSocket(request);

    // Set up event listeners for the WebSocket
    webSocket.addEventListener('open', (event) => {
        // WebSocket connection opened
        console.log('WebSocket connection opened');
    });

    webSocket.addEventListener('message', (event) => {
        // WebSocket message received
        console.log('WebSocket message received:', event.data);
    });

    webSocket.addEventListener('close', (event) => {
        // WebSocket connection closed
        console.log('WebSocket connection closed:', event.code, event.reason);
    });

    // Return the WebSocket response
    return webSocket.response;
}

/**
 * Converts a remote socket to a WebSocket connection using VMess protocol.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vmessResponseHeader The VMess response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, vmessResponseHeader, retry, log) {
    // remote --> ws
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let vmessHeader = vmessResponseHeader;
    let hasIncomingData = false; // check if remoteSocket has incoming data
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {},
                /**
                 * @param {Uint8Array} chunk
                 * @param {*} controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    remoteChunkCount++;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe closed'
                        );
                    }
                    if (vmessHeader) {
                        webSocket.send(await new Blob([vmessHeader, chunk]).arrayBuffer());
                        vmessHeader = null;
                    } else {
                        console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
                        // If you want to rate limit, you can add a delay here
                        // Example: await delay(1); // Delay for 1 millisecond
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is closed with hasIncomingData is ${hasIncomingData}`);
                    // safeCloseWebSocket(webSocket); // No need to close the WebSocket from the server first, as it may cause issues
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(
                `remoteSocketToWS has an exception `,
                error.stack || error
            );
            safeCloseWebSocket(webSocket);
        });

    // Check if there was an error in the remoteSocket or if it didn't receive any data
    if (!hasIncomingData && retry) {
        log(`retry`);
        retry();
    }
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection using VMess protocol.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vmessResponseHeader The VMess response header.
 * @param {(string) => void} log The logging function.
 * @returns {{ write: (chunk: Uint8Array) => void }} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vmessResponseHeader, log) {
    let isVMessHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {},
        transform(chunk, controller) {
            // UDP message format: 2 bytes for the length of UDP data followed by UDP data
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPacketLength)
                );
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {},
    });

    // Handle DNS queries and send them over the WebSocket
    transformStream.readable.pipeTo(
        new WritableStream({
            async write(chunk) {
                const resp = await fetch(dohURL, {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                });
                const dnsQueryResult = await resp.arrayBuffer();
                const udpSize = dnsQueryResult.byteLength;
                const udpSizeBuffer = new Uint8Array([
                    (udpSize >> 8) & 0xff,
                    udpSize & 0xff,
                ]);
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    log(`DNS UDP success, message length is ${udpSize}`);
                    if (isVMessHeaderSent) {
                        webSocket.send(
                            await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer()
                        );
                    } else {
                        webSocket.send(
                            await new Blob([vmessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer()
                        );
                        isVMessHeaderSent = true;
                    }
                }
            },
        })
    ).catch((error) => {
        log('DNS UDP error: ' + error);
    });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         * @param {Uint8Array} chunk
         */
        write(chunk) {
            writer.write(chunk);
        },
    };
}

/**
 * Generates VMess configuration for multiple users.
 * @param {string} userIDs - Single or comma-separated user IDs.
 * @param {string | null} hostName - The hostname or domain name.
 * @returns {string} The VMess configuration.
 */
function generateVMessConfig(userIDs, hostName) {
    const commonURLPart = `:${vmessPort}?security=auto&host=${hostName}`;
    const separator = "---------------------------------------------------------------";

    // Split the userIDs into an array
    const userIDArray = userIDs.split(',');

    // Prepare the output array
    const output = [];

    // Generate VMess configuration for each user
    userIDArray.forEach((userID) => {
        const vmessURL = `vmess://${userID}${commonURLPart}`;
        output.push(`User ID: ${userID}`);
        output.push(`${separator}\n${vmessURL}\n${separator}`);
    });

    return output.join('\n');
}

// Example usage:
const userIDs = "your-user-ids"; // Replace with your user IDs
const hostName = "your-hostname"; // Replace with your hostname or domain name
const vmessPort = 443; // Replace with your VMess port
const vmessConfig = generateVMessConfig(userIDs, hostName);
console.log(vmessConfig); // Output the generated VMess configuration

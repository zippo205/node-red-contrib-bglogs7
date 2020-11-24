module.exports = function(RED) {
	"use strict";
	const TPKT_HEADSIZE = 4;
	const TPKT_VERSION = 0x03;
	const TPKT_RESERVE = 0x00;
	// TPDU constants
	const TPDU_MINSIZE = 3;
	const TPDU_HEADER_LENGTH = 0x02;
	const TPDU_DATA = 0xF0;
	const TPDU_CR = 0xE0;                 // Connection Request
	const TPDU_CC = 0xD0;                 // Connection Confirm
	const TPDU_EOT = 0x80;                // End of transmission
	const TPDU_SIZE_COMMAND = 0xC0;
	const TPDU_CALLING_COMMAND = 0xC1;
	const TPDU_CALLED_COMMAND = 0xC2;
	const TPDU_CLASS = 0x00;
	const TOTAL_HEADER_LENGTH = TPKT_HEADSIZE + TPDU_MINSIZE;
	//Beumer Protocol constants
	const BGLOG_HEADER_LEN=16;
	const BGLOG_TRAILER_LEN=2;
	const BGLOG_INNER_HEADER_LEN=4;
	
	var reconnectTime = RED.settings.socketReconnectTime||10000;
	var socketTimeout = RED.settings.socketTimeout||120000;
	var socketKeepAliveTime = RED.settings.socketKeepAliveTime||60000;
	
    var net = require('net');

	function createCRMsg(node) { 
		let tpduSize = 11;                          // tpduSize and tpduSizeInBytes must always match together
		let tpduSizeInBytes = 2048;                 // tpduSizeInBytes = 2^tpduSize = 2^11
		let externalConnectionID = 0;
		let connectionID = 1000;
		let localtsap = node.localtsap; // e.g.:  "MC01LG01";
		let remotetsap = node.remotetsap; //e.g.: "MC01LG01";
		let tpdulen = 13 + localtsap.length + remotetsap.length;
		let tpktlen = TPKT_HEADSIZE + 1 + tpdulen;
		//create buffer for cr message
		let idx = 0;
		const buf = Buffer.allocUnsafe(tpktlen);
		buf[idx++] = TPKT_VERSION;
		buf[idx++] = TPKT_RESERVE;
		// TPKT header: total length (16-bit). Byteswap length data to Big Endian (MSB first)
		buf.writeUInt16BE(tpktlen,2);
		idx += 2;
		// TPDU length
		buf[idx++] = tpdulen;
		// Set C0 param as Connection Request
		buf[idx++] = TPDU_CR;
		// Set destination ID (16-bit). Byteswap ID to Big Endian (MSB first)
		buf.writeUInt16BE(externalConnectionID,idx);
		idx += 2;
		// Set source ID (16-bit). Byteswap ID to Big Endian (MSB first)
		buf.writeUInt16BE(connectionID,idx);
		idx += 2;
		// Set RFC1006 class 0
		buf[idx++] = 0;
		// Set TPDU size (number of bits)
		buf[idx++] = TPDU_SIZE_COMMAND;
		buf[idx++] = 0x01;                   // LG = 1
		buf[idx++] = tpduSize;
		// Set calling TSAP (local)
		buf[idx++] = TPDU_CALLING_COMMAND;
		buf[idx++] = localtsap.length;
		for(let i=0; i<localtsap.length; i++) {
			buf[idx++] = (localtsap.charCodeAt(i));
		}
		// Set called TSAP (remote)
		buf[idx++] = TPDU_CALLED_COMMAND;
		buf[idx++] = remotetsap.length;
		for(let i=0; i<remotetsap.length; i++) {
			buf[idx++] = (remotetsap.charCodeAt(i));
		}
		return buf;
	}
	
	function parseTPDUMsg(node,data,enablelog=false) {
		let offset = 0;
		let exit = false;
		let msgCounter = 0;
		if(node && data && Buffer.isBuffer(data)){
			while(!exit){
				// Enough bytes for the length info bytes itself received ?
				if (data.length >= BGLOG_HEADER_LEN + offset){
					//parse the header
					let h_source = data.toString('utf8',offset, offset + 4);
					let h_dest = data.toString('utf8',offset+4,offset+8);
					let seq_str = data.toString('utf8',offset+8,offset+10);
					let len_str = data.toString('utf8',offset+10,offset+16);
					let seq = parseInt(seq_str);
					let len = parseInt(len_str);
					if(enablelog)
						node.log("Received log message block. H_Source=<" + h_source + ">, H_Dest=<" + h_dest + ">, Seq=<" + seq + ">, Len=<" + len + ">");
					//check if data len fits
					if(len > (BGLOG_HEADER_LEN + BGLOG_TRAILER_LEN) && len + offset <= data.length){
						let buf = Buffer.allocUnsafe(len - (BGLOG_HEADER_LEN + BGLOG_TRAILER_LEN) );
						//buffer.copy(target, targetStart, sourceStart, sourceEnd);
						data.copy(buf,0,offset + BGLOG_HEADER_LEN, offset + len - BGLOG_TRAILER_LEN);
						if(enablelog)
							node.log("Copy inner messages to buffer. BufLen=<"+buf.length+">");
						let innerOffset = 0;
						let innerExit = false;
						while(!innerExit){
							if(innerOffset === 0){
								if(enablelog)
									node.log("Start parsing log messages. BufLen=<"+buf.length+">, Offset=<"+innerOffset+"> , HeaderLen=<"+BGLOG_INNER_HEADER_LEN+">");
							}
							else{
								if(enablelog)
									node.log("Continue parsing log messages. BufLen=<"+buf.length+">, Offset=<"+innerOffset+"> , HeaderLen=<"+BGLOG_INNER_HEADER_LEN+">");
							}
							if (buf.length >= BGLOG_INNER_HEADER_LEN + innerOffset){
								let msgType = buf.toString('utf8',innerOffset,innerOffset+2);
								let msglen = buf.readUInt16BE(innerOffset+2);
								if(enablelog)
									node.log("Inner log message. Type=<" + msgType + ">, Len=<" + msglen + ">");
								if(msglen > BGLOG_INNER_HEADER_LEN && msglen + innerOffset <= buf.length){
									let innerBuf = Buffer.allocUnsafe(msglen-BGLOG_INNER_HEADER_LEN);
									buf.copy(innerBuf,0,innerOffset + BGLOG_INNER_HEADER_LEN,innerOffset+msglen);
									let msg1 = {topic:"LO_Msg","host":node.host,"port":node.port,payload:innerBuf};
									node.send(msg1);
									innerOffset += msglen;
									msgCounter++;
								}
								else{
									node.error("Parsing log message length error occured. Type=<" + msgType + ">, Len=<" + msglen + ">");
									innerExit=true;
								}
							}
							else{
								if(buf.length === innerOffset){
									if(enablelog)
										node.log("Parsing done. count=<" + msgCounter + ">");
								}
								else{
									node.error("Parsing error.");
								}
								innerExit=true;
							}
						}
						offset += len;
					}
					else{
						//error
						exit = true;
					}
				}
				else
				{
					 exit = true;
				}
			}
		}
	}	

	function BgLogS7(n) {
        RED.nodes.createNode(this,n);
        this.topic = n.topic;
		this.host = n.server;
        this.port = n.port * 1;
		this.localtsap = n.localtsap;
		this.remotetsap = n.remotetsap;
		this.node_closing = false;
        this.connected = false;
		this.tcp_closing = false;
		this.isRFC1006initialized = false;
		this.connection_id = this.host + ":" + this.port + "," + this.localtsap + "," + this.remotetsap;
		this.enablelog = n.enablelog;
		this.enablepassthrough = n.enablepassthrough;
		this.passthroughport = n.passthroughport;
		
        var node = this;
		//tcp client
		var client = null;
		var server = null;
		var connectedSockets = [];
		var reconnectTimeout;
		var initRFC1006Timeout;
		var closeConTimeout;
		
		var initRFC1006TimeoutHandler = function() {
			if(node.connected && !node.node_closing && !node.tcp_closing && !node.isRFC1006initialized){
				//close connection
				if(node.enablelog)
					node.warn("Warn RFC1006 init timeout. Close connection! host=<" + node.host + ">, port=<" + node.port + ">");
				node.status({fill:"gray",shape:"ring",text:"closing"});
				node.tcp_closing = true;
				client.end();
				closeConTimeout = setTimeout(closeConTimeoutHandler,5000);
			}
		}
		
		var closeConTimeoutHandler = function() {
			if(node.connected && node.tcp_closing){
				//close connection
				if(node.enablelog)
					node.warn("Failed to close connection. Use destroy to kill it. host=<" + node.host + ">, port=<" + node.port + ">");
				node.tcp_closing = false;
				node.connected = false;
				if(client){
					client.destroy();
				}
				if (!node.node_closing) {
					reconnectTimeout = setTimeout(setupTcpClient,100);
				}
			}
		}
		
		var setupPassThroughTcpServer = function() {
			if(node.enablepassthrough && node.passthroughport > 0){
				server = net.createServer(function (socket) {
					socket.setKeepAlive(true,socketKeepAliveTime);
					if (socketTimeout !== null) { socket.setTimeout(socketTimeout); }
					node.log("Add socket connected to passthrough TCP server. remoteaddress=<" + socket.remoteAddress + ">, remoteport=<" + socket.remotePort + ">");
					connectedSockets.push(socket);
					socket.on('timeout', function() {
						node.warn("Received socket timeout event for passthrough server!");
						socket.end();
					});
					socket.on('close',function() {
						node.log("Received socket close event for passthrough server! remoteaddress=<" + socket.remoteAddress + ">, remoteport=<" + socket.remotePort + ">");
						connectedSockets.splice(connectedSockets.indexOf(socket),1);
					});
					socket.on('error',function() {
						node.error("Received socket error event for passthrough server! remoteaddress=<" + socket.remoteAddress + ">, remoteport=<" + socket.remotePort + ">");
						connectedSockets.splice(connectedSockets.indexOf(socket),1);
					});
				});
				
				server.on('error', function(err) {
				if (err) {
						node.error("Received error event for passthrough server! error=<" + err.toString() + ">");
					}
				});

				server.listen(node.passthroughport, function(err) {
					if (err) {
						node.error("Error on listen command for passthrough server! listenport=<" + node.passthroughport +">, error=<" + err.toString() + ">");
					} else {
						node.log("Start listnening on passthrough server. listenport=<" + node.passthroughport +">");
						node.on('close', function() {
							for (var c in connectedSockets) {
								if (connectedSockets.hasOwnProperty(c)) {
									node.log("Close socket connected to passthrough server. remoteaddress=<" + c.remoteAddress + ">, remoteport=<" + c.remotePort + ">");
									connectedSockets[c].end();
									connectedSockets[c].unref();
								}
							}
							server.close();
							node.log("Close passthrough server. listenport=<" + node.passthroughport +">");
						});
					}
				});
			}
		}
		setupPassThroughTcpServer();
		
		var setupTcpClient = function() {
			if (node.host && node.port && node.localtsap && node.remotetsap) {
				if(node.enablelog)
					node.log("Setup client host=<" + node.host + ">, port=<" + node.port + ">, ltsap=<"+ node.localtsap + ">, rtsap=<" + node.remotetsap + ">, keepalive=<" +socketKeepAliveTime + ">, timeout=<" + socketTimeout +">");
				node.status({fill:"grey",shape:"dot",text:"connecting"});
				client = net.Socket();
				if (socketTimeout !== null)
					{ client.setTimeout(socketTimeout);}
				client.setKeepAlive(true,socketKeepAliveTime);
				client.connect(node.port, node.host, function() {
					if(node.enablelog)
						node.log("Client connected. Send CR to init RFC1006. host=<" + node.host + ">, port=<" + node.port + ">, ltsap=<"+ node.localtsap + ">, rtsap=<" + node.remotetsap + ">");
					node.connected = true;
					//create CR message and send it
					node.status({fill:"blue",shape:"dot",text:"initRFC1006"});
					var cr_msg = createCRMsg(node);
					client.write(cr_msg);
					node.isRFC1006initialized = false;
					initRFC1006Timeout = setTimeout(initRFC1006TimeoutHandler,5000);
				});
				client.on('error', function (err) {
					node.error("Error occured! host=<" + node.host + ">, port=<" + node.port + ">, error=<"+ err.toString() + ">");
					node.status({fill:"red",shape:"dot",text:"error"});
                });
				client.on('end', function (err) {
					if(node.enablelog)
						node.log("Received connction end event! host=<" + node.host + ">, port=<" + node.port + ">");
                    node.status({});
                    node.connected = false;
                });
				client.on('close', function() {
					if(node.enablelog)
						node.log("Received connection close event! host=<" + node.host + ">, port=<" + node.port + ">");
                    node.status({fill:"red",shape:"ring",text:"disconnected"});
                    node.connected = false;
					node.tcp_closing = false;
					clearTimeout(closeConTimeout);
                    client.destroy();
                    if (!node.node_closing) {
						if(node.enablelog)
							node.warn("Connection closed! Trigger reconnect. host=<" + node.host + ">, port=<" + node.port + ">");
						reconnectTimeout = setTimeout(setupTcpClient,reconnectTime);
                    } 
					else {
                        if (node.doneClose) { 
							node.doneClose(); 
						}
                    }
                });
				client.on('timeout',function() {
					if (!node.node_closing) {
						//node.connected = node.isRFC1006initialized = node.tcp_closing = false;
						//clearTimeout(initRFC1006Timeout);
						if(node.enablelog)
							node.warn("Received connection timeout event! Close socket. host=<" + node.host + ">, port=<" + node.port + ">");
						node.status({fill:"grey",shape:"dot",text:"timeout"});
						node.tcp_closing = true;
						client.destroy();
						/*if (!node.node_closing) {
							if(node.enablelog)
								node.warn("Trigger reconnect. host=<" + node.host + ">, port=<" + node.port + ">");
							reconnectTimeout = setTimeout(setupTcpClient,reconnectTime);
						} 
						else {
							if (node.doneClose) { 
								node.doneClose(); 
							}
						}*/
					}
                });

				client.on('data', function (data) {
					let msg1;
					let error = false;
					let tlgLength = 0;
					let offset = 0;
					
					try {
						//node.log("Received data! BytesRead=<" + data.length + ">");
						node.log("Received data! BytesRead=<" + client.bytesRead + ">");
						if(Buffer.isBuffer(data)){
							do{
								if (data.length - offset < TPKT_HEADSIZE){
									if(node.enablelog)
										node.warn("Received data with invalid length! MinLength=<" +TPKT_HEADSIZE + ">, host=<" + node.host + ">, port=<" + node.port + ">");
									error = true;
								}
								if(!error){
									if ((data[0 + offset] != TPKT_VERSION) || (data[1 + offset] != TPKT_RESERVE))
									{
										node.error("Error Invalid header.");
										if(node.enablelog)
											node.warn("Received data with invalid header! host=<" + node.host + ">, port=<" + node.port + ">");
										error = true;
									}
								}
								if(!error){
									// Valid TPKT header - find length of whole telegram (16-bit). Byteswap length from Big Endian (MSB first)
									tlgLength = data.readUInt16BE(2 + offset);
									if (tlgLength < TOTAL_HEADER_LENGTH){
										if(node.enablelog)
											node.warn("Error - TPKT header length value invalid. Length=<" + tlgLength + ">, Expect min.=<" + TOTAL_HEADER_LENGTH + ">, host=<" + node.host + ">, port=<" + node.port + ">");
										error = true;
									}
									else{
										if ((data.length - offset) < tlgLength){
											node.error("Received not the complete telegram. Length=<" + (data.length - offset) + ">, Expected=<" + tlgLength + ">, host=<" + node.host + ">, port=<" + node.port + ">");
											//todo add to buffer
											error = true;
										}
									}
								}
								if(!error){
									//Look at Byte "6" for Type definition of the Protocol. Header 4+1=5 but Array starts with 0 so its 6 at location 5
									let tlgType = data[TPKT_HEADSIZE + 1 + offset];
									switch (tlgType){
										case TPDU_DATA:
											//handle TPDU data
											//Datalen defines the real Data contained in this Package except header and reserved stuff
											let datalen = tlgLength - TOTAL_HEADER_LENGTH;
											if(node.enablelog)
												node.log(`Received TPDU data. Length=<${tlgLength}>, host=<${node.host}>, port=<${node.port}>`);
											
											if (data[TPKT_HEADSIZE +  offset] !== TPDU_HEADER_LENGTH){
												error = true;
											}
											else{
												if (data[TPKT_HEADSIZE + 2 + offset] !== TPDU_EOT){
													//todo add to buffer
													node.error(`Message incomplete, Fragmentation in todo! host=<${node.host}>, port=<${node.port}>`);
												}
												else{
													let buf2 = Buffer.allocUnsafe(datalen);
													data.copy(buf2,0, TOTAL_HEADER_LENGTH + offset, tlgLength + offset);
													//redirect to server
													if(node.enablepassthrough){
														for (var i = 0; i < connectedSockets.length; i += 1) {
															connectedSockets[i].write(buf2);
														}
													}
													//extract paylod
													node.log(`Extract TPDU payload and forward it. MsgLength=<${tlgLength}>, PayloadLen=<${datalen}>`);
													parseTPDUMsg(node,buf2,node.enablelog);
													//msg1 = {topic:"tpdu_data","host":node.host,"port":node.port,payload:buf2};
													//node.log("Extract TPDU payload and forward it. MsgLength=<" + tlgLength + ">, PayloadLen=<" + datalen + ">");
													//node.send(msg1);
												}
											}
										   break;
										case TPDU_CR:
											node.error(`Received Connection Request (CR) telegram! host=<${node.host}>, port=<${node.port}>`);
											break;
										case TPDU_CC:
											if(node.enablelog)
												node.log(`Received Connection Confirm (CC) telegram. MsgLength=<${tlgLength}>, host=<${node.host}>, port=<${node.port}>`);
											clearTimeout(initRFC1006Timeout);
											node.isRFC1006initialized = true;
											node.status({fill:"green",shape:"dot",text:"connected"});
											break;
										 default:
											node.error(`Received unknown message type! host=<${node.host}>, port=<${node.port}>`);
											error = true;
											break;
									}
								}
								if(!error){
									offset += tlgLength;
								}
							}while(!error && (data.length - offset) > 0);
						}
						else{
							node.error(`Received invalid data format. Has to be a byte buffer! host=<${node.host}>, port=<${node.port}>`);
						}
					}
					catch(err) {
						node.error(`Exception occured! error=<${err.toString()}>`);
					}
					finally {
					}
				});
			}
			else{
				node.warn(RED._("bglog.errors.no-host"));
			}
		}
		setupTcpClient();
		
		node.on("input", function(msg, nodeSend, nodeDone) {
			var host = node.host || msg.host;
            var port = node.port || msg.port;	
			var localtsap = node.localtsap || msg.localtsap;
			var remotetsap = node.remotetsap || msg.remotetsap;	
			var connection_id = host + ":" + port + "," + localtsap + "," + remotetsap;
			if(msg.hasOwnProperty("enablelog")){
				node.enablelog = msg.enablelog;
			}
			var restart = false;
			if(msg.hasOwnProperty("restart")){
				if(msg.restart === true)
					restart = true;
			}
			if(connection_id !== node.connection_id || restart){
				var oldhost = node.host;
				var oldport = node.port;
				var oldlocaltsap = node.localtsap;
				var oldremotetsap = node.remotetsap;
				node.host = host;
				node.port = port;
				node.localtsap = localtsap;
				node.remotetsap = remotetsap;
				node.connection_id = connection_id;
				clearTimeout(initRFC1006Timeout);
                clearTimeout(reconnectTimeout);
				//check if already connected 
				if (client) { 
					if(node.connected && !node.tcp_closing){
						if(node.enablelog)
							node.log(`Client already connected. Close it first. oldhost=<${oldhost}>, oldport=<${oldport}>, oldltsap=<${oldlocaltsap}>, oldrtsap=<${oldremotetsap}>`);
						node.status({fill:"gray",shape:"ring",text:"closing"});
						node.tcp_closing = true;
						client.end();
						closeConTimeout = setTimeout(closeConTimeoutHandler,5000);
					}
					else{
						if(node.enablelog)
							node.log("There is a client but not connected. Go on with setup. oldhost=<" + oldhost + ">, oldport=<" + oldport + ">, oldltsap=<"+ oldlocaltsap + ">, oldrtsap=<" + oldremotetsap + ">");
						node.status({fill:"red",shape:"ring",text:"disconnected"});
						client.destroy();
						setupTcpClient();
					}
				}
				else{
					node.status({});
					if(node.enablelog)
						node.log("Start setup client. oldhost=<" + oldhost + ">, oldport=<" + oldport + ">, oldltsap=<"+ oldlocaltsap + ">, oldrtsap=<" + oldremotetsap + ">");
					setupTcpClient();
				}
			}
			if(nodeDone){
				nodeDone();
			}
		});
		
		node.on("close", function(done) {
			if(node.enablelog)
				node.log("Close node event received!");
			node.doneClose = done;
			node.node_closing = true;
			if (client) { client.destroy(); }
			clearTimeout(closeConTimeout);
			clearTimeout(initRFC1006Timeout);
			clearTimeout(reconnectTimeout);
			if (server) { server.close(); }
			if (!node.connected) { done(); }
		});
	}
	
    RED.nodes.registerType("bglogs7",BgLogS7);
}
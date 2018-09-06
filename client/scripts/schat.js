/*
const libp2p = require('libp2p');
const TCP = require('libp2p-tcp');
const PeerInfo = require('peer-info');
const async = require('async');
const defaultsDeep = require('@nodeutils/defaults-deep');
const parallel = require('async/parallel');
const pull = require('pull-stream');
const SPDY = require('libp2p-spdy')
const SECIO = require('libp2p-secio')

class MyBundle extends libp2p {
    constructor (_options) {
      const defaults = {
        modules: {
          transport: [ TCP ],
          streamMuxer: [ SPDY ],
          connEncryption: [ SECIO ]
        }
      }
  
      super(defaultsDeep(_options, defaults))
    }
  }
  
  function createNode (callback) {
    let node
  
    waterfall([
      (cb) => PeerInfo.create(cb),
      (peerInfo, cb) => {
        peerInfo.multiaddrs.add('/ip4/0.0.0.0/tcp/0');
        node = new MyBundle({ peerInfo: peerInfo })
        node.start(cb)
      }
    ], (err) => callback(err, node))
  }
  
  function printAddrs (node, number) {
    console.log('node %s is listening on:', number)
    node.peerInfo.multiaddrs.forEach((ma) => console.log(ma.toString()))
  }
  
  function print (protocol, conn) {
    pull(
      conn,
      pull.map((v) => v.toString()),
      pull.log()
    )
  }
  
  parallel([
    (cb) => createNode(cb)
  ], (err, nodes) => {
    if (err) { throw err }
  
    const node1 = nodes[0]
    
    printAddrs(node1, '1')
   
    node1.handle('/print', print)
    

    node1.dialProtocol(node2.peerInfo, '/print', (err, conn) => {
      if (err) { throw err }
  
      pull(pull.values(['node 1 dialed to node 2 successfully']), conn)
    })
  })
*/


$(function() {

    const stun = require('stun')
    const NodeRSA = require("node-rsa");
    const publicIP = require('public-ip'); 
    const dgram = require('dgram');
    var CryptoJS = require("crypto-js");

    var localKey = new NodeRSA({b: 512});
    var remoteKey = new NodeRSA(null, 'pkcs8-public-pem');
    
    var remoteAddress = "127.0.0.1";
    var localPort = 8087;
    var remotePort = localPort;

    var identityBase = "oGXU8I3X7oLfOrAR";

    loadKey = function(key) {
        try {
            remoteKey.importKey(key, "public");
        } catch(err) {
            $("#remote-identity").val("Invalid public key (PKCS8-PUBLIC-PEM)");
        }
    }

    generateNewKeypair = function(bitCount) {
        localKey = new NodeRSA({b: bitCount});
        localKey.setOptions({encryptionScheme: 'pkcs1_oaep'});
    }

    outputKeys = function() {
        const publicKey = localKey.exportKey("public"); 
        const privateKey = localKey.exportKey("private"); 
        $("#local-public").val(publicKey);
        $("#local-private").val(privateKey);
    }

    sendMessage = function(msg) {
        if(remoteKey.isEmpty()) {
            outputMessage("Error: remote key is empty, cannot encrypt message.")
            return;
        }
        if(checkNullOrWhiteSpace(msg)) { return; }
        outputMessage("Local -> " + remoteAddress + ": " +  msg);
        const eMsg = remoteKey.encrypt(msg, 'base64');
        const message = Buffer.from(eMsg);
        server.send(message, 0, message.length, remotePort, remoteAddress);
    }

    receiveMessage = function(msg, rinfo) {
        var ueMsg = "UNDEFINED";
        try {
            ueMsg = localKey.decrypt(new String(msg), 'utf8');
        } catch(err) {
            outputMessage(rinfo.address + ":" + rinfo.port + " has sent you an incorrectly encrypted message.");
            return;
        }
        outputMessage("Local <- " + remoteAddress + ": " +  ueMsg);
    }

    checkNullOrWhiteSpace = function(str) {
        return (/^\s*$/.test(str) || !str || str.length === 0)
    }

    outputMessage = function(msg) {
        $("#message-output").append(msg + "\n");
        console.log(`[OUT] ${msg}`);
    }

    verifyB64 = function(msg) 
    {
        var b64t = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;
        return b64t.test(msg);
    }

    getSocket = function() 
    {
        return dgram.createSocket({"reuseAddr": true, "type": "udp4"});  
    }

    calculateID = function() {
        let identityStr = $("#local-public").val() + "@" + $("#local-address").val() + "@" + $("#local-port").val();
        console.log("Made identity:" + identityStr);
        let identity = CryptoJS.AES.encrypt(identityStr, identityBase);
        $("#local-identity").val(identity);
    }

    setupServer = function() 
    {
        publicIP.v4().then(ip => {
            console.log(`[IP] Your public IP is ${ip}`);
        });

        if(!$("#local-port").val() || !$("#local-address").val()) {
            const { STUN_BINDING_REQUEST, STUN_ATTR_XOR_MAPPED_ADDRESS } = stun.constants
            
            const stunServer = stun.createServer()
            const request = stun.createMessage(STUN_BINDING_REQUEST)     
            stunServer.once('bindingResponse', stunMsg => {
                let adr = stunMsg.getAttribute(STUN_ATTR_XOR_MAPPED_ADDRESS).value.address
                let prt = stunMsg.getAttribute(STUN_ATTR_XOR_MAPPED_ADDRESS).value.port
                console.log(`[STUN] Connected to ${adr}:${prt}`)
                if(!$("#local-address").val()) {
                    $("#local-address").val(adr);
                }
                if(!$("#local-port").val()) {
                    $("#local-port").val(prt);
                    localPort = $("#local-port").val();
                }
                stunServer.close()
            })      
            stunServer.send(request, 19302, 'stun.l.google.com')
        }


        try {
            server.close();
        } catch (err) {
            console.warn(`[UDP4] Server could not be closed; server being re-initialized`); 
        } finally {
            console.log(`[UDP4] Server socket created`);
            server = getSocket();
        }
        server.on('error', (err) => {
            console.error(`[UDP4] Server error:\n${err.stack}`);
            server.close();
        });

        server.on('message', (msg, rinfo) => {
            console.log(`[UDP4] Server received data [${msg}] from ${rinfo.address}:${rinfo.port}`);
            if(verifyB64(msg)) {
                receiveMessage(msg, rinfo);
            } else {
                console.log(`[UDP4] You've been sent an invalid message from ${rinfo.address}:${rinfo.port}`);
            }
        });

        server.on('listening', () => {
            let address = server.address();
            
            console.log(`[UDP4] Server listening on ${address.address}:${address.port}`);
        });

        server.bind(localPort);
    }

    $("#b-local-keypair").click(function() {
        let bitCount = $("#local-bitcount").val(); 
        if(bitCount % 8 == 0) {
            if(bitCount >= 8 && bitCount <= 16384) {       
                generateNewKeypair(bitCount);
                outputKeys();
                calculateID();
            } else {
                $("#local-keypair").val("The bitcount must be between 8-32,768");
            }
        } else {
            $("#local-keypair").val("The bitcount must be a multiple of 8 (512, 8, 2048, 1024)");
        }
    });

    $("#b-remote-address").click(function() {
        let ra = $("#remote-address").val();
        remoteAddress = ra;
        localPort = $("#local-port").val();
        setupServer();
        console.log("Updated remote address");
    });

    $("#b-remote-identity").click(function() {
        let identity = $("#remote-identity").val();
        let b_identity = CryptoJS.AES.decrypt(identity, identityBase.toString());
        let r_identity = b_identity.toString(CryptoJS.enc.Utf8);
        console.log(r_identity);
        var s_identity = r_identity.split("@");

        remoteAddress = s_identity[1];
        remotePort = s_identity[2];
        console.log(`[Identity] Remote port set to ${remoteAddress}:${remotePort}`);

        loadKey(s_identity[0]);
        console.log("[Identity] Updated remote public key");

        setupServer();
    });

    $("#message-input").keypress(function(e) {
        let msg =  $("#message-input").val();
        if(e.which == 13) {
            $("#message-input").val('');
            sendMessage(msg);
        }
    });


   setupServer();
    
   // const text = 'Hello RSA!';
   // const encrypted = key.encrypt(text, 'base64');
   // console.log('encrypted: ', encrypted);
   // const decrypted = key.decrypt(encrypted, 'utf8');
   // console.log('decrypted: ', decrypted);
});
 


$(function() {

    const NodeRSA = require("node-rsa");
    const publicIP = require('public-ip'); 
    const dgram = require('dgram');
    const UdpHolePuncher = require('udp-hole-puncher');
    var CryptoJS = require("crypto-js");

    var localKey = new NodeRSA({b: 512});
    var remoteKey = new NodeRSA(null, 'pkcs8-public-pem');
    
    var remoteAddress = "127.0.0.1";
    var localPort = 8087;
    var remotePort = localPort;

    var identityBase = "oGXU8I3X7oLfOrAR";

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
            if(!$("#local-address").val()) {
                $("#local-address").val(ip);
            }
            if(!$("#local-port").val()) {
                $("#local-port").val("8017");
            }
            localPort = $("#local-port").val();
        });

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
            
            const puncher = new UdpHolePuncher(server, 
                {maxRequestAttempts: 15, requestTimeout: 250}
            );

            puncher.on('reachable', () => {
                console.log(`[UDP Hole Puncher (1/2)] Reached into ${remoteAddress}:${remotePort}!`);
            })

            puncher.on('connected', () => {
                console.log(`[UDP Hole Puncher (2/2)] Punched into ${remoteAddress}:${remotePort}!`);
            });

            puncher.on('error', (error) => {
                console.error(`[UDP Hole Puncher] Error ${error}`);
                puncherc.close();
            });

            puncher.connect(remoteAddress, remotePort);

            const address = server.address();
            console.log(`[UDP4] Server listening on ${address.address}:${address.port}`);
        });

        server.bind(localPort);
    }

    setupServer();
    
   // const text = 'Hello RSA!';
   // const encrypted = key.encrypt(text, 'base64');
   // console.log('encrypted: ', encrypted);
   // const decrypted = key.decrypt(encrypted, 'utf8');
   // console.log('decrypted: ', decrypted);
});
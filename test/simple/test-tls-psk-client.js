// Copyright & License details are available under JXCORE_LICENSE file

if (process.env.CITEST) {
    console.error('Skipping test due to CITEST environment variable. (old openssl.exe)');
    process.exit(0);
}
if (!process.versions.openssl) {
    console.error("Skipping because node compiled without OpenSSL.");
    process.exit(0);
}
if (parseInt(process.versions.openssl[0]) < 1) {
    console.error("Skipping because node compiled with old OpenSSL version.");
    process.exit(0);
}


var common = require('../common');
var join = require('path').join;
var net = require('net');
var assert = require('assert');
var fs = require('fs');
var crypto = require('crypto');
var tls = require('tls');
var spawn = require('child_process').spawn;

// FIXME: Avoid the common PORT as this test currently hits a C-level
// assertion error with node_g. The program aborts without HUPing
// the openssl s_server thus causing many tests to fail with
// EADDRINUSE.
var PORT = common.PORT + 5;

var pskey = "d731ef57be09e5204f0b205b60627028";
var identity = 'Client_identity';   // openssl s_client supports specifying the identity but s_server, oddly, does not

var sharedHint = "foobar";

var PSKCiphers = 'PSK-AES256-CBC-SHA:PSK-3DES-EDE-CBC-SHA:PSK-AES128-CBC-SHA:PSK-RC4-SHA';


var useTestServer = true;
var forcedClosed = false;

if (useTestServer) {
    var server = spawn('openssl', ['s_server',
        '-accept', PORT,
        '-psk', pskey,
        '-psk_hint', sharedHint,
        '-nocert']);
    server.stdout.pipe(process.stdout);
    server.stderr.pipe(process.stdout);


    var state = 'WAIT-ACCEPT';

    var serverStdoutBuffer = '';
    server.stdout.setEncoding('utf8');
    server.stdout.on('data', function (s) {
        serverStdoutBuffer += s;
        console.error(state);
        switch (state) {
            case 'WAIT-ACCEPT':
                if (/ACCEPT/g.test(serverStdoutBuffer)) {
                    // Give s_server a second to start up.
                    setTimeout(startClient, 1000);
                    state = 'WAIT-HELLO';
                }
                break;

            case 'WAIT-HELLO':
                if (/hello/g.test(serverStdoutBuffer)) {

                    // End the current SSL connection and exit.
                    // See s_server(1ssl).
                    server.stdin.write('Q');
                    forcedClosed = true;
                    state = 'WAIT-SERVER-CLOSE';
                }
                break;

            default:
                break;
        }
    });


    var timeout = setTimeout(function () {
        server.kill();
        process.exit(1);
    }, 5000);

    var gotWriteCallback = false;
    var serverExitCode = -1;

    server.on('exit', function (code) {
        serverExitCode = code;
        clearTimeout(timeout);
    });

}

function startClient() {
    var s = new net.Stream();

    var sslcontext = crypto.createCredentials({});
    sslcontext.context.setCiphers(PSKCiphers);

    function clientCallback(hint) {
        assert.equal(sharedHint, hint);
        if (hint == sharedHint) {
            console.log('+++ in client callback');
            return {
                identity: identity,
                key: new Buffer(pskey, 'hex')
            }
        }
        return null;
    }

    var pair = tls.createSecurePair(sslcontext, false, null, null, clientCallback);

    assert.ok(pair.encrypted.writable);
    assert.ok(pair.cleartext.writable);

    pair.encrypted.pipe(s);
    s.pipe(pair.encrypted);

    s.connect(PORT);

    s.on('connect', function () {
        console.log('client connected');
    });

    pair.once   ('secure', function () {
        console.log('client: connected+secure!');
        console.log('client pair.cleartext.getCipher(): %j',
            pair.cleartext.getCipher());
        setTimeout(function () {
            pair.cleartext.write('hello\r\n', function () {
                gotWriteCallback = true;
            });
        }, 500);
    });

    pair.cleartext.on('data', function (d) {
        console.log('cleartext: %s', d.toString());
    });

    s.on('close', function () {
        console.log('client close');
    });

    pair.encrypted.on('error', function (err) {
        console.log('encrypted error: ' + err);
    });

    s.on('error', function (err) {
        if (forcedClosed)
            console.log('closed by server - OK');
        else 
            console.log('socket error: ' + err);
    });

    pair.on('error', function (err) {
        console.log('secure error: ' + err);
    });
}

startClient();

process.on('exit', function () {
    assert.equal(0, serverExitCode);
    assert.equal('WAIT-SERVER-CLOSE', state);
    assert.ok(gotWriteCallback);
});

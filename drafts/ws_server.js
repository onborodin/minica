#!/usr/bin/env node

var WebSocket = require('ws');
var WebSocketServer = require('ws').Server;
var request = require('request');

var wss;
wss = new WebSocketServer({ port: 9088 });

wss.on('connection', function connection(server) {
    console.log('Web connected');
    server.on('message', function incoming(m) {
        console.log('received: %s', m);
        server.send( m );
        console.log('sended: %s', m);
    });
});

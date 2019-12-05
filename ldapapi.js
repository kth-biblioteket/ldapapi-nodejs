/**
 *
 * API mot LDAP.
 *
 */

require('dotenv').config()
var express = require("express");
var bodyParser = require("body-parser");
var jwt = require("jsonwebtoken");
//var xml = require('xml');
//var jsonxml = require('jsontoxml');
var js2xmlparser = require("js2xmlparser");
var VerifyToken = require('./VerifyToken');

var app = express();

const ActiveDirectory = require('activedirectory');

var config = { url: process.env.HOST,
                baseDN: process.env.BASEDN,
                username: process.env.LDAPUSER,
                password: process.env.PASSWORD,
                tlsOptions: {
                    rejectUnauthorized: false
                },
                attributes: {
                    user: [ 'dn',
                    'userPrincipalName', 'sAMAccountName', 'mail',
                    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
                    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
                    'comment', 'description', 'memberOf','ugAffiliation'],
                    group: [ 'dn', 'cn', 'description' ]
                }
            }
var ad = new ActiveDirectory(config);

app.set('apikeyread', process.env.APIKEYREAD);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(function (req, res, next) {
	var whitelist = ['kth.se', 'lib.kth.se']
  	var host = req.get('host');

	whitelist.forEach(function(val, key){
		if (host.indexOf(val) > -1){
			res.setHeader('Access-Control-Allow-Origin', host);
		}
	});
	res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
	res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType,Content-Type, Accept, Authorization");
	next();
});

var apiRoutes = express.Router();

apiRoutes.get('/', function(req, res) {
	res.send('Hello! The API is at https://lib.kth.se/ldap/api/v1');
});


apiRoutes.post("/login", function(req, res) {
	ad.authenticate(req.body.username, req.body.password, function(err, auth) {
		if (err) {
		  	res.status(400).send({ auth: false, error: err });
		} else {
			if (auth) {
			var token = jwt.sign({ id: req.body.username }, process.env.SECRET, {
				expiresIn: 86400
			});
			
			res.status(200).send({ auth: true, token: token });
			}
			else {
			res.status(401).send({ auth: false, token: null });
			}
		}
	  });
});

apiRoutes.get('/logout', function(req, res) {
	res.status(200).send({ auth: false, token: null });
});

apiRoutes.get("/kthid/:kthid/", VerifyToken, function(req , res, next){
	ad.find('ugKthid=' + req.params.kthid, function(err, results) {
		if ((err)) {
			res.status(400).send({ 'result': 'Error: ' + err});
			return;
		}
		if ((! results)) {
			res.status(400).send({ 'result': 'kthid ' + req.params.kthid + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users[0]});
		} else {
			res.json({'result': 'nothing'});
		}
	});
});

apiRoutes.get("/account/:account/", VerifyToken, function(req, res, next){
    ad.find('sAMAccountName=' + req.params.account, function(err, results) {
		if ((err)) {
			res.status(400).send({ 'result': 'Error: ' + err});
			return;
		}
		if ((! results)) {
			res.status(400).send({ 'result': 'Account ' + req.params.account + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users[0]});
			//xmlres = js2xmlparser.parse("uguser", users.users[0]);
			//res.type('application/xml');
            //res.send(xmlres);
		} else {
			res.json({'result': 'nothing'});
		}
    });
});

app.use('/ldap/api/v1', apiRoutes);

var server = app.listen(process.env.PORT || 3002, function () {
    var port = server.address().port;
    console.log("App now running on port", port);
});
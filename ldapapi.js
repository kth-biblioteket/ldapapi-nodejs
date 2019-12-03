/**
 *
 * API mot LDAP.
 *
 */

require('dotenv').config()
var express = require("express");
var bodyParser = require("body-parser");
//var xml = require('xml');
//var jsonxml = require('jsontoxml');
var js2xmlparser = require("js2xmlparser");

var app = express();

const ActiveDirectory = require('activedirectory');

var config = { url: process.env.HOST,
                baseDN: process.env.BASEDN,
                username: process.env.USERNAME,
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
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType,Content-Type, Accept, Authorization");
	next();
});

var apiRoutes = express.Router();

apiRoutes.get('/', function(req, res) {
	res.send('Hello! The API is at https://lib.kth.se/ldap/api/v1');
});

apiRoutes.use(function(req, res, next) {
	var token = req.body.token || req.query.token || req.headers['x-access-token'];
	if (token) {
		  if(token != app.get('apikeyread')){
			  return res.json({ success: false, message: 'Failed to authenticate token.' });
		  } else {
			  next();
		  }
	} else {
	  return res.status(403).send({
		  success: false,
		  message: 'No token provided.'
	  });
	}
});

apiRoutes.get("/kthid/:kthid/", function(req , res){
	ad.find('ugKthid=' + req.params.kthid, function(err, results) {
		if ((err) || (! results)) {
			console.log('ERROR: ' + JSON.stringify(err));
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users[0]});
		} else {
			res.json({'result': 'nothing'});
		}
	});
});

apiRoutes.get("/account/:account/", function(req , res){
    ad.find('sAMAccountName=' + req.params.account, function(err, results) {
		if ((err) || (! results)) {
			console.log('ERROR: ' + JSON.stringify(err));
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
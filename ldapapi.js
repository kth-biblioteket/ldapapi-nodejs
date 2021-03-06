require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const VerifyToken = require('./VerifyToken');

const app = express();

const ActiveDirectory = require('activedirectory');

const config = { url: process.env.HOST,
                baseDN: process.env.BASEDN,
                username: process.env.LDAPUSER,
                password: process.env.PASSWORD,
                tlsOptions: {
                    rejectUnauthorized: false
                },
                attributes: {
                    user: [ 'dn',
                    'userPrincipalName', 'sAMAccountName', 'mail',
					'lockoutTime', 'whenCreated', 'whenChanged',
					'pwdLastSet', 'lastLogon', 'userAccountControl',
                    'employeeID', 'employeeType', 'sn', 'givenName', 'initials', 'cn', 'displayName',
					'comment', 'description', 'title', 'department', 'memberOf', 'ugAffiliation',
					'ugPrimaryAffiliation', 'company', 'uid',
					'ugClass','ugKthid','ugVersion','ugUsername','ugPhone','kthPAGroupMembership','textEncodedORAddress',
					'streetAddress', 'l', 'postalCode', 'c', 'telephoneNumber', 'homePhone',
					'proxyAddresses', 'extensionAttribute1', 'extensionAttribute2'],
                    group: [ 'dn', 'cn', 'description' ]
                }
            }
const ad = new ActiveDirectory(config);

app.set('apikeyread', process.env.APIKEYREAD);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//CORS

app.use(function (req, res, next) {
	var whitelist = ['kth.se', 'lib.kth.se', 'kth.diva-portal.org']
	/*  
	var origin = req.get('origin');
	whitelist.forEach(function(val, key){
		if (origin.indexOf(val) > -1){
			res.setHeader('Access-Control-Allow-Origin', origin);
		}
	});
	*/
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
	res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, contentType,Content-Type, Accept, Authorization, x-access-token");
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
					expiresIn: "7d"
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
			res.status(201).send({ 'result': 'kthid ' + req.params.kthid + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users});
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
			res.status(201).send({ 'result': 'Account ' + req.params.account + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users[0]});
		} else {
			res.json({'result': 'nothing'});
		}
    });
});

apiRoutes.get("/userprincipalname/:userprincipalname/", VerifyToken, function(req, res, next){
    ad.find('userPrincipalName=' + req.params.userprincipalname, function(err, results) {
		if ((err)) {
			res.status(400).send({ 'result': 'Error: ' + err});
			return;
		}
		if ((! results)) {
			res.status(201).send({ 'result': 'Userprincipalname ' + req.params.userprincipalname + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users[0]});
		} else {
			res.json({'result': 'nothing'});
		}
    });
});

apiRoutes.get("/users/:name/", VerifyToken, function(req, res, next){
    ad.find('cn=' + req.params.name , function(err, results) {
		if ((err)) {
			res.status(400).send({ 'result': 'Error: ' + err});
			return;
		}
		if ((! results)) {
			res.status(201).send({ 'result': 'Users ' + req.params.users + ' not found'});
			return;
		}
		if(results.users) {
			res.json({"ugusers" :results.users});
		} else {
			res.json({'result': 'nothing'});
		}
    });
});

/**
 * 
 * Hämta apinycklar för divaapan
 * 
 * Vilka ska ha behörighet till dem?
 * 
 * Alla på bibblan ()
 * 
 * pa.anstallda.T.TR	KTH BIBLIOTEKET	
 * pa.anstallda.T.TRAA	VERSAMHETSSTÖD	
 * pa.anstallda.T.TRAB	BIBL.SERVICE & LÄRANDE STÖD	
 * pa.anstallda.T.TRAC	PUBLICERINGENS INFRASTRUKTUR
 * 
 */
apiRoutes.post("/divamonkey", VerifyToken, function(req, res) {
	//req.userprincipalname = hämtas från jwt-token
	ad.find('userPrincipalName=' + req.userprincipalname, function(err, results) {
		if ((err)) {
			res.status(400).send({ 'result': 'Error: ' + err});
			return;
		}
		if ((! results)) {
			res.status(201).send({ 'result': 'Userprincipalname ' + req.params.userprincipalname + ' not found'});
			return;
		}
		if(results.users) {
			if(results.users[0].kthPAGroupMembership) {
				if(results.users[0].kthPAGroupMembership.indexOf('pa.anstallda.T.TR') !== -1 ) {
					res.json(
						{
							"apikeys" : {
								"ldap": process.env.LDAPAPIKEY,
								"orcid": process.env.ORCIDAPIKEY,
								"letaanstallda": process.env.LETAANSTALLDAAPIKEY,
								"scopus": process.env.SCOPUSAPIKEY,
							},
							"token": req.token
						});
				} else {
					res.status(201).send({"result" :'not authorized monkeyuser'});
				}

			} else {
				res.status(201).send({"result" :'not authorized monkeyuser'});
			}
		} else {
			res.status(400).send({'result': 'General error'});
		}
    });
});

app.use('/ldap/api/v1', apiRoutes);

var server = app.listen(process.env.PORT || 3002, function () {
    var port = server.address().port;
    console.log("App now running on port", port);
});
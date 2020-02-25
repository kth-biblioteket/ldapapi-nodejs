function verifyToken(req, res, next) {
    var isjwt = req.body.fake || req.query.fake || req.headers['x-access-token'];
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (!token)
        return res.status(403).send({ auth: false, message: 'No token provided.' });
    
    if (!isjwt) {
        if(token != process.env.APIKEYREAD){
            return res.json({ success: false, message: 'Failed to authenticate token.' });
        } else {
            next();
        }
    } else {
        jwt.verify(token, process.env.SECRET, function(err, decoded) {
            if (err)
                return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
            req.userId = decoded.id;
            next();
        });
    }
}

module.exports = verifyToken;
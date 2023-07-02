var express = require("express");
var session = require('express-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var saml = require('passport-saml');
var fs = require('fs');
var app = express();
var userProfile;

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(session({secret: 'secret', 
                 resave: false, 
                 saveUninitialized: true,}));

app.get('/',
    function(req, res) {
        res.send('Test Home Page');
    }
);

var server = app.listen(4300, function () {
    console.log('Listening on port %d', server.address().port)
});

passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    done(null, user);
});

var samlStrategy = new saml.Strategy({
    // config options here
    path: '/login/callback',
    callbackUrl: 'http://localhost:4300/login/callback',
    entryPoint: 'http://localhost:9000/simplesaml/saml2/idp/SSOService.php',
    logoutUrl: 'http://localhost:9000/simplesaml/saml2/idp/SingleLogoutService.php',
    issuer: 'saml-poc',
    identifierFormat: null,
    decryptionPvk: fs.readFileSync(__dirname + '/certs/key.pem', 'utf8'),
    privateCert: fs.readFileSync(__dirname + '/certs/key.pem', 'utf8'),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true
  }, function(profile, done) {
    userProfile = profile;
    return done(null, profile);
  });

passport.logoutSaml = function(req, res) {
    //Here add the nameID and nameIDFormat to the user if you stored it someplace.
    req.user.nameID = req.user.saml.nameID;
    req.user.nameIDFormat = req.user.saml.nameIDFormat;

    samlStrategy.logout(req, function(err, request){
        if(!err){
            //redirect to the IdP Logout URL
            console.log("Redirecting to home")
            res.redirect(request);
        }
    });
};
passport.use('samlStrategy', samlStrategy);
app.use(passport.initialize({}));
app.use(passport.session({}));


app.get('/login',
    function (req, res, next) {
        next();
    },
    passport.authenticate('samlStrategy'),
);

app.post('/login/callback',
    function (req, res, next) {
        next();
    },
    passport.authenticate('samlStrategy'),
    function (req, res) {
        res.send('Logged in as ' + req.user.email);
    }
);
app.get('/login/callback', function(req, res){
    res.send('Logged out');
})

app.get('/logout', function(req, res){
    req.user = {
        nameID: userProfile.nameID,
        nameIDFormat: userProfile.nameIDFormat,
    }
    samlStrategy.logout(req, function(err, requestUrl) {
        req.logout();
        res.redirect(requestUrl);
    });
});
passport.logoutSamlCallback = function(req, res){
    req.logout();
    res.redirect('/');
}
app.post('/logout/callback', passport.logoutSamlCallback);

app.get('/metadata',
    function(req, res) {
        res.type('application/xml'); 
        res.status(200).send(
          samlStrategy.generateServiceProviderMetadata(
             fs.readFileSync(__dirname + '/certs/cert.pem', 'utf8'), 
             fs.readFileSync(__dirname + '/certs/cert.pem', 'utf8')
          )
        );
    }
);
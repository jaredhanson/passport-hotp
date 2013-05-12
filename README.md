# Passport-HOTP

[Passport](http://passportjs.org/) strategy for two-factor authentication using
a [HOTP](http://tools.ietf.org/html/rfc4226) value.

This module lets you authenticate using a HOTP value in your Node.js
applications.  By plugging into Passport, HOTP two-factor authentication can be
easily and unobtrusively integrated into any application or framework that
supports [Connect](http://www.senchalabs.org/connect/)-style middleware,
including [Express](http://expressjs.com/).  HOTP values can be generated by
hardware devices or software applications, including [Google Authenticator](https://code.google.com/p/google-authenticator/).

Note that in contrast to most Passport strategies, HOTP authentication requires
that a user already be authenticated using an initial factor.  Requirements
regarding when to require a second factor are a matter of application-level
policy, and outside the scope of both Passport and this strategy.

## Install

    $ npm install passport-hotp

## Usage

#### Configure Strategy

The HOTP authentication strategy authenticates a user using a HOTP value
generated by a hardware device or software application (known as a token).  The
strategy requires a `setup` callback and a `resync` callback.

The `setup` callback accepts a previously authenticated `user` and calls `done`
providing a `key` and `counter` used to verify the HOTP value.  Authentication
fails value is not verified.

After successful authentication, the `resync` callback is invoked to synchronize
the counter values on the server and on the token.

    passport.use(new HotpStrategy(
      function(user, done) {
        HotpKey.findOne({ userId: user.id }, function (err, key) {
          if (err) { return done(err); }
          return done(null, key.key, key.counter);
        });
      },
      function(user, key, counter, delta, done) {
        HotpKey.update(user.id, { key: key, counter: counter }, function (err, key) {
          if (err) { return done(err); }
          return done();
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'hotp'` strategy, to authenticate
requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/verify-otp', 
      passport.authenticate('hotp', { failureRedirect: '/verify-otp' }),
      function(req, res) {
        req.session.authFactors = [ 'hotp' ];
        res.redirect('/');
      });

## Examples

For a complete, working example, refer to the [two-factor example](https://github.com/jaredhanson/passport-hotp/tree/master/examples/two-factor).

## Tests

    $ npm install
    $ make test

[![Build Status](https://secure.travis-ci.org/jaredhanson/passport-hotp.png)](http://travis-ci.org/jaredhanson/passport-hotp)

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
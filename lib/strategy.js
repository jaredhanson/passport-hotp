/**
 * Module dependencies.
 */
var passport = require('passport')
  , hotp = require('notp').hotp
  , util = require('util');


/**
 * `Strategy` constructor.
 *
 * The HOTP authentication strategy authenticates requests based on the
 * HOTP value submitted through an HTML-based form.
 *
 * Applications must supply a `setup` callback which accepts `user`, and then
 * calls the `done` callback supplying a `key` and `counter` used to verify the
 * HOTP value.  A `resync` callback must also be supplied, which is used to
 * resynchronize the counter value after successful authentication.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `codeField`  field name where the HOTP value is found, defaults to _code_
 *   - `window`     size of look-ahead synchronization window, defaults to 50
 *
 * Examples:
 *
 *     passport.use(new HotpStrategy(
 *       function(user, done) {
 *         HotpKey.findOne({ userId: user.id }, function (err, key) {
 *           if (err) { return done(err); }
 *           return done(null, key.key, key.counter);
 *         });
 *       },
 *       function(user, key, counter, delta, done) {
 *         HotpKey.update(user.id, { key: key, counter: counter }, function (err, key) {
 *           if (err) { return done(err); }
 *           return done();
 *         });
 *       }
 *     ));
 *
 * References:
 *  - [HOTP: An HMAC-Based One-Time Password Algorithm](http://tools.ietf.org/html/rfc4226)
 *  - [KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
 *
 * @param {Object} options
 * @param {Function} setup
 * @param {Function} resync
 * @api public
 */
function Strategy(options, setup, resync) {
  if (typeof options == 'function') {
    resync = setup;
    setup = options;
    options = {};
  }
  
  this._codeField = options.codeField || 'code';
  this._window = options.window !== undefined ? options.window : 50;
  
  passport.Strategy.call(this);
  this._setup = setup;
  this._resync = resync;
  this.name = 'hotp';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on HOTP values.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var value = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);
  
  var self = this;
  this._setup(req.user, function(err, key, counter) {
    if (err) { return self.error(err); }
    
    var rv = hotp.verify(value, key, { window: self._window, counter: counter });
    if (!rv) { return self.fail(); }
    self._resync(req.user, key, (counter + rv.delta + 1), rv.delta, function(err) {
      if (err) { return self.error(err); }
      return self.success(req.user);
    });
  });
  
  
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

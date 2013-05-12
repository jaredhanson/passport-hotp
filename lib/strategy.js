/**
 * Module dependencies.
 */
var passport = require('passport')
  , hotp = require('notp').hotp
  , util = require('util');


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
    self._resync(req.user, key, (counter + rv.delta + 1), rv.delta, function(err, props) {
      if (err) { return self.error(err); }
      // merge `props` into `req.session`, allowing application to keep state
      // about authentication factors
      if (req.session && props) { merge(req.session, props); }
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
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

function merge(a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

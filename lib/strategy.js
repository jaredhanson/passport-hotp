/**
 * Module dependencies.
 */
var passport = require('passport')
  , hotp = require('notp').hotp
  , util = require('util');


function Strategy(options, setup) {
  if (typeof options == 'function') {
    setup = options;
    options = {};
  }
  
  this._codeField = options.codeField || 'code';
  
  passport.Strategy.call(this);
  this._setup = setup;
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
  var code = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);
  
  this._setup(req.user, function(err, key) {
    if (err) { return self.error(err); }
    
    var rv = hotp.verify(code, key, { window: 50, counter: 0 });
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

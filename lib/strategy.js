/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util');


function Strategy(options, verify) {
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

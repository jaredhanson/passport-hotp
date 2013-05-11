var hotp = require('index');


describe('passport-hotp', function() {
    
  it('should export version', function() {
    expect(hotp.version).to.be.a('string');
  });
    
  it('should export Strategy', function() {
    expect(hotp.Strategy).to.be.a('function');
  });
  
});

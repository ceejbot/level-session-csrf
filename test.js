/*global describe:true, it:true, before:true, after:true */

var
	demand = require('must'),
	sinon  = require('sinon'),
	CSRF   = require('./index')
	;

describe('level-session-csrf', function()
{
	describe('exports', function()
	{
		it('exports a function', function()
		{
			CSRF.must.be.a.function();
		});

		it('exports its internals for testing', function()
		{
			CSRF.must.have.property('findValue');
			CSRF.findValue.must.be.a.function();
			CSRF.must.have.property('saltedToken');
			CSRF.saltedToken.must.be.a.function();
			CSRF.must.have.property('createToken');
			CSRF.createToken.must.be.a.function();
			CSRF.must.have.property('checkToken');
			CSRF.checkToken.must.be.a.function();
			CSRF.must.have.property('generateSalt');
			CSRF.generateSalt.must.be.a.function();
		});

	});

	describe('middleware', function()
	{
		it('the middleware returns a function', function()
		{
			var func = CSRF();
			func.must.be.a.function();
		});

	});

	describe('findValue()', function()
	{
		it('returns a _csrf field on the body object', function()
		{
			var req = { body: { _csrf: 'foo '}};
			var result = CSRF.findValue(req);
			result.must.equal(req.body._csrf);
		});

		it('returns a _csrf field in the query', function()
		{
			var req = { body: 'whatever', query: { _csrf: 'query' }};
			var result = CSRF.findValue(req);
			result.must.equal(req.query._csrf);
		});

		it('finds the x-csrf-token header', function()
		{
			var req = { headers: { 'x-csrf-token': 'header'} };
			var result = CSRF.findValue(req);
			result.must.equal('header');
		});

		it('finds the x-xsrf-token header', function()
		{
			var req = { headers: { 'x-xsrf-token': 'header'} };
			var result = CSRF.findValue(req);
			result.must.equal('header');
		});
	});

	describe('saltedToken()', function()
	{
		it('calls generateSalt() and createToken()', function()
		{
			var spy1 = sinon.spy(CSRF, 'generateSalt');
			var spy2 = sinon.spy(CSRF, 'createToken');

			var result = CSRF.saltedToken('i am a secret');
			spy1.called.must.be.true();
			spy2.called.must.be.true();

			spy1.restore();
			spy2.restore();
		});

		it('creates a token', function()
		{
			var result = CSRF.saltedToken('i am a secret');
			result.must.be.a.string();
			result.length.must.equal(54);
		})
	});

	describe('createToken()', function()
	{
		it('has tests');
	});

	describe('checkToken()', function()
	{
		it('returns false for bad input', function()
		{
			var result = CSRF.checkToken({ object: 'yes' }, 'i am a secret');
			result.must.be.false();
		});

		it('returns true for a good token', function()
		{
			var secret = 'this is a secret';
			var good = CSRF.saltedToken(secret);
			var result = CSRF.checkToken(good, secret);
			result.must.be.true();
		});

		it('returns false for a bad token', function()
		{
			var result = CSRF.checkToken('this is some text that cannot possibly be valid', 'i am a secret');
			result.must.be.false();
		});
	});

	describe('generateSalt()', function()
	{
		it('returns a random string of the specified length', function()
		{
			var r = CSRF.generateSalt(10);
			r.must.be.a.string();
			r.length.must.equal(10);

			var r2 = CSRF.generateSalt(10);
			r2.must.not.equal(r);

			r = CSRF.generateSalt(64);
			r.length.must.equal(64);
		});
	});
});

var
	assert = require('assert'),
	crypto = require('crypto'),
	http   = require('http'),
	Puid   = require('puid')
	;

var puid = new Puid();

var csrf = module.exports = function csrf(options)
{
	options = options || {};
	var value = options.value || csrf.findValue;

	function middleware(request, response, next)
	{
		request.session.get('_csrfSecret', function(err, stored)
		{
			if (err) return next(err);
			if (!stored)
			{
				stored = puid.generate();
				request.session.set('_csrfSecret', stored, function(err)
				{
					if (err) return next(err);
					validate(stored);
				});
			}
			else
			{
				validate(stored);
			}

			function validate(secret)
			{
				// Decorate the request with a lazy-evaluation token-getter function.
				var token;
				request.csrfToken = function csrfToken()
				{
					return token || (token = csrf.saltedToken(secret));
				};

				// Enforce a match, but only for http verbs that modify resources.
				if ('GET' == request.method || 'HEAD' == request.method || 'OPTIONS' == request.method)
					return next();

				var passedIn = value(request);
				if (!csrf.checkToken(passedIn, secret))
				{
					var error = new Error(http.STATUS_CODES[403]);
					error.status = 403;
					error.csrf = 'CSRF token mismatch';
					return next(error);
				}

				next();
			}
		});
	}

	return middleware;
};

csrf.findValue = function findValue(request)
{
	return (request.body && request.body._csrf) ||
		(request.query && request.query._csrf) ||
		(request.headers['x-csrf-token']) ||
		(request.headers['x-xsrf-token']);
};

csrf.saltedToken = function saltedToken(secret)
{
	return csrf.createToken(csrf.generateSalt(10), secret);
};

csrf.createToken = function createToken(salt, secret)
{
	assert(salt && (typeof salt === 'string'), 'salt must be a string');
	assert(secret && (typeof secret === 'string'), 'secret must be a string');
	return salt + crypto.createHash('sha256').update(salt + secret).digest('base64');
};

csrf.checkToken = function checkToken(token, secret)
{
	if ('string' != typeof token) return false;

	var tmp = csrf.createToken(token.slice(0, 10), secret);
	return (token === tmp);
};

var SALTCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

csrf.generateSalt = function generateSalt(length)
{
	var r = [];
	for (var i = 0; i < length; ++i)
		r.push(SALTCHARS[Math.floor(Math.random() * SALTCHARS.length)]);

	return r.join('');
};

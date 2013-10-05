var
	crypto = require('crypto'),
	http   = require('http'),
	Puid   = require('puid')
	;

var puid = new Puid();

module.exports = function csrf(options)
{
	options = options || {};
	var value = options.value || findValue;

	function middleware(request, response, next)
	{
		request.session.get('_csrfSecret', function(err, secret)
		{
			if (err) return next(err);
			if (!secret)
				secret = puid.generate();

			// Decorate the request with a lazy-evaluation token-getter function.
			var token;
			request.csrfToken = function csrfToken()
			{
				return token || (token = saltedToken(secret));
			};

			// Enforce a match, but only for http verbs that modify resources.
			if ('GET' == req.method || 'HEAD' == req.method || 'OPTIONS' == req.method)
				return next();

			var passedIn = value(request);

			if (!checkToken(passedIn, secret))
			{
				var error = new Error(http.STATUS_CODES[code]);
				error.status = code;
				error.csrf = 'CSRF token mismatch';
				return next(error);
			}

			next();
		});
	}

	return middleware;
};

function findValue(request)
{
	return (request.body && request.body._csrf) ||
		(request.query && request.query._csrf) ||
		(request.headers['x-csrf-token']) ||
		(request.headers['x-xsrf-token']);
}

function saltedToken(secret)
{
	return createToken(generateSalt(10), secret);
}

function createToken(salt, secret)
{
	return salt + crypto.createHash('sha256').update(salt + secret).digest('base64');
}

function checkToken(token, secret)
{
	if ('string' != typeof token) return false;
	return (token === createToken(token.slice(0, 10), secret));
}

var SALTCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateSalt(length)
{
	var r = [];
	for (var i = 0; i < length; ++i)
		r.push(SALTCHARS[Math.floor(Math.random() * SALTCHARS.length)]);

	return r.join('');
}


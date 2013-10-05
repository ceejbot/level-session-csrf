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
					return token || (token = saltedToken(secret));
				};

				// Enforce a match, but only for http verbs that modify resources.
				if ('GET' == request.method || 'HEAD' == request.method || 'OPTIONS' == request.method)
					return next();

				var passedIn = value(request);
				if (!checkToken(passedIn, secret))
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

	var tmp = createToken(token.slice(0, 10), secret);
	return (token === tmp);
}

var SALTCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateSalt(length)
{
	var r = [];
	for (var i = 0; i < length; ++i)
		r.push(SALTCHARS[Math.floor(Math.random() * SALTCHARS.length)]);

	return r.join('');
}


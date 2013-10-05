# level-session-csrf

Connect middleware that implements csrf tokens backed by a level-session store. API-compatible with [connect/csrf](http://www.senchalabs.org/connect/csrf.html).

## Usage

```javascript
	var csrf = require('level-session-csrf');

	var sessiondb = require('level-session')(
	{
		location: path.join(config.dbpath, 'sessions.db'),
		expire:   app.SESSION_TTL,
		keys:     config.secrets
	});

	var app = express();
	app.use(sessiondb);
	app.use(csrf());
```

Then to add the token to the locals for any specific request:

```javascript
response.render('template', { '_csrf': request.csrfToken() });
```

The middleware by default assumes that you are providing the token in a form or query parameter named `_csrf`, or in a request header called `x-csrf-token` or `x-xsrf-token`.

## Options

You can optionally pass an options object to `csrf()` to specify a custom value-checking function. The value-checking function is passed the request object, which it may inspect as it wishes. The function must return a token string. For instance, if you wanted to look at a custom form parameter instead of `_csrf`:

```javascript
function customValue(request)
{
	return request.body.my_form_parameter;
}

var options = { 'value': customValue };
app.use(csrf(options));
```

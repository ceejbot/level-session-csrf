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
request.locals._csrf = request.csrfToken();
```

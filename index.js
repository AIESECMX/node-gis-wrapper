var request = require('request');

module.exports = EXPA;

function EXPA(username, password, enforceSSL){
	"use strict";

	var r = request.defaults({
		rejectUnauthorized: typeof enforceSSL !== 'boolean' ? true : enforceSSL,
		jar: true,
		followAllRedirects: true,
		qsStringifyOptions: {arrayFormat: 'brackets'}
	});

	var _ = {},
	_baseUrl = 'https://gis-api.aiesec.org/v2',
	_token;

	var tokenRequest = () => new Promise((resolve, reject) => {
    r.get('https://experience-v2.aiesec.org/auth', (error, response, body) => {
			var match = body.match('<meta.*content="(.*)".*name="csrf-token"');

			r.post({
				url: 'https://auth.aiesec.org/users/sign_in',
				form: {
					"user[email]": username,
					"user[password]": password,
					"authenticity_token": match[1],
					"commit": 'Sign in'
				}
			}, function(error, response, body){
				if(error) {
					reject(error);
				} else {
					if(body.indexOf('<h2>Invalid email or password.') > -1){
						reject('Invalid email or password');
					} else {
						response.body = body;
						resolve(response);
					}
				}
			});

		});
	});

	 _.getNewToken = function() {
		return tokenRequest().then((response) => {
	 		var cookie = response.req._headers.cookie;
	 		var token = cookie.match('expa_token=(.*)')[1].replace(/;.*/, '');
	 		_token = token;
	 		return token;
	 	});
	};

	 _.getToken = function(){
	 	if(_token) {
	 		return Promise.resolve(_token);
	 	} else {
	 		return _.getNewToken();
	 	}
	 };

	_.request = (uri, options) => new Promise((resolve, reject) => {
		var params = {};
		if (typeof options === 'object') {
			Object.assign(params, options, {uri: uri});
		} else if (typeof uri === 'string') {
			Object.assign(params, {uri: uri});
		} else {
			Object.assign(params, uri);
		}

		if(params.uri.indexOf('http') < 0) params.baseUrl = _baseUrl;

		params.callback = function(err, resp, body){
			if(err) {
				reject(err);
			} else {
				try{
					var json = JSON.parse(body);
					if(json.status && json.status.code == 401) {
						//if token expired, get new one and retry
						_.getNewToken().then(function(){
							_.request(uri, options)
							.then(resolve)
							.catch(reject);
						});
					} else {
						resolve(json);
					}
				} catch(e) {
					resolve(body);
				}
				
			}
		};

		_.getToken().then(function(token){
			params.uri += `?access_token=${token}`;
			r(params);
		}, reject);
	});

	_.get = function(url, data){
		return _.request(url, {
			form: data
		});
	};

	_.post = function(url, data){
		return _.request(url, {
			method: "POST",
			form: data
		});
	};

	_.patch = function(url, data){
		return _.request(url, {
			method: "PATCH",
			form: data
		});
	};

	return _;
}

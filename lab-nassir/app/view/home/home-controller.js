'use strict';

require('./_home.scss');

module.exports = ['$log', HomeController ];

function HomeController($log){
  $log.debug('init homeCtrl');
  this.oneAtATime = true;

  let googleAuthBase = 'https://accounts.google.com/o/oauth2/v2/auth';
  let googleAuthResponseType = 'response_type=code';
  let googleAuthClientID = `client_id=${__GOOGLE_CLIENT_ID__}`;
  let googleAuthRedirectURI = 'redirect_uri=http://localhost:3000/api/auth/oauth_callback';
  let googleAuthScope = 'scope=profile%20email%20openid';
  let googleAuthAccessType = 'access_type=offline';

  this.googleAuthURL = `${googleAuthBase}?${googleAuthResponseType}&${googleAuthClientID}&${googleAuthRedirectURI}&${googleAuthScope}&${googleAuthAccessType}`;

}

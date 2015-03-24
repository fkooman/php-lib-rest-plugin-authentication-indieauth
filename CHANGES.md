# Release History

## 0.2.1
- update dependencies and spec file

## 0.2.0
- implement logout support
- add CSRF protection for auth and logout endpoints
- update `fkooman/rest`
- **BREAKING**: uniform redirectTo support, `redirect_to` is now set in post to 
  `indieauth/auth` and no longer through `IndieAuthAuthentication` constructor. 
  For logout the query parameter `redirect_to` is used
- validate and normalize the `redirect_to` URL

## 0.1.3
- support `application/x-www-form-urlencoded` response to verify request again

## 0.1.2
- for now break `indieauth.com` until they fix the `Accept` header on verify 
  endpoint and no longer require `state` POST parameter on verify
- rework session usage, remove redundant `state` POST variable when verifying
  code
- require normalized version of provided `me` field as `me` in the verification
  response (also must be fixed at `indieauth.com` to follow normalization 
  rules
- default to `https://indiecert.net/auth` when discovery is disabled or 
  fails

## 0.1.1
- allow disabling discovery (distributed IndieAuth)

## 0.1.0 
- initial release

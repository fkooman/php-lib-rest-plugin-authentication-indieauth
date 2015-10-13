# Release History

## 1.0.2 (2015-10-13)
- update tests to work with new `fkooman/http`

## 1.0.1 (2015-09-21)
- make `isAttempt()` also return true if an unauthorized redirect uri is set
  because that allows for a redirect to the login page
- `urlencode()` the `redirect_to` parameter to be able to redirect to URLs 
  containing query parameters after the login
- add a test for the case where an unauthorized redirect uri is set
- no longer explicitly enable the `ReferrerCheckPlugin` as it is enabled by
  default now and more intelligent
- use external `fkooman/io` project for IO class, no longer embed our own
  version

## 1.0.0 (2015-07-21)
- initial release

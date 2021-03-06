# Release History

## 3.0.0 (2016-08-19)
- update `fkooman/rest` and `fkooman/http` dependencies

## 2.0.2 (2016-05-25)
- update `fkooman/io`

## 2.0.1 (2016-03-25)
- update `fkooman/json` and move to development dependencies
- fix TestTemplateManager API compatilibty

## 2.0.0 (2016-01-22)
- update API to new `fkooman/rest-plugin-authentication`
- lots of code cleanup

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

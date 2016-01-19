[![Build Status](https://travis-ci.org/fkooman/php-lib-rest-plugin-authentication-indieauth.svg?branch=master)](https://travis-ci.org/fkooman/php-lib-rest-plugin-authentication-indieauth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-lib-rest-plugin-authentication-indieauth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-lib-rest-plugin-authentication-indieauth/?branch=master)

# Introduction
This plugin enables one to use IndieAuth authentication with `fkooman/rest`.

# API
The plugin works by registering three endpoints under `/_auth/indieauth` in 
the `fkooman/rest` framework:

* `/_auth/indieauth/auth` 
* `/_auth/indieauth/callback`
* `/_auth/indieauth/logout`

So if your application is running under `https://www.example.org/foo`, the 
`/indieauth/auth` endpoint becomes 
`https://www.example.org/foo/indieauth/auth`.

## Authentication
The `/_auth/indieauth/auth` endpoint accepts a `POST` containing the `me` 
parameter with the URL to the user's homepage and the optionally the 
`redirect_to` parameter. If the `redirect_to` field is missing the browser will 
redirect back to the application root.

So for example to ask the user for their home page and redirecting
them to `https://www.example.org/foo/profile` after successful authentication
you can use the following `<form>`:

    <form method="post" action="_auth/indieauth/auth">
        https://<input type="text" name="me" placeholder="example.org" required>
        <input type="hidden" name="redirect_to" value="https://www.example.org/foo/profile">
        <input type="submit" value="Sign In">
    </form>

The POST to the `/_auth/indieauth/auth` endpoint will take care of validating 
and normalizing the provided URL and determining "Distributed IndieAuth" 
support by performing discovery.

The callback will take care of receiving the authentication code from the 
IndieAuth service and validating it. Then it will redirect the browser back to
`redirect_to`. Nothing needs to be configured for that.

## Logout
You can send a POST to `/_auth/indieauth/logout` to log out of the session. 
An optional form parameter `redirect_to` can be used to redirect to a specific
URL. If it is omitted the browser is redirected to the application root, 
for example:

    <form method="post" action="_auth/indieauth/logout">
        <input type="hidden" name="redirect_to" value="https://www.example.org/foo/welcome">
        <input type="submit" value="Logout">
    </form>


[![Build Status](https://travis-ci.org/fkooman/php-lib-rest-plugin-indieauth.svg?branch=master)](https://travis-ci.org/fkooman/php-lib-rest-plugin-indieauth)

# Introduction
This plugin enables one to use IndieAuth authentication with `fkooman/rest`.

See `example/indieauth.php` for an example on how to use this in your 
application.

# API
The plugin works by registering three endpoints under `/indieauth` in the 
`fkooman/rest` framework:

* `/indieauth/auth` 
* `/indieauth/callback`
* `/indieauth/logout`

So if your application is running under `https://www.example.org/foo`, the 
`/indieauth/auth` endpoint becomes 
`https://www.example.org/foo/indieauth/auth`.

## Authentication
The `/indieauth/auth` endpoint accepts a `POST` containing the `me` parameter 
with the URL to the user's homepage and the optionally the `redirect_to` 
parameter. If the `redirect_to` field is missing the browser will redirect back 
to the application root.

So for example to ask the user for their home page and redirecting
them to `https://www.example.org/foo/profile` after successful authentication
you can use the following `<form>`:

    <form method="post" action="indieauth/auth">
        https://<input type="text" name="me" placeholder="example.org" required>
        <input type="hidden" name="redirect_to" value="/profile">
        <input type="submit" value="Sign In">
    </form>

The POST to the `/indieauth/auth` endpoint will take care of validating and
normalizing the provided URL and determining "Distributed IndieAuth" support.

The callback will take care of receiving the authentication code from the 
IndieAuth service and validating it. Then it will redirect the browser back to
`redirect_to`. Nothing needs to be configured for that.

## Logout
You can redirect the browser to `/indieauth/logout` to log out of the session. 
An optional query parameter `redirect_to` can be used to redirect to a specific
URL. If it is omitted the browser is redirected to the application root.

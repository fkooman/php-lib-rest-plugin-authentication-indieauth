[![Build Status](https://travis-ci.org/fkooman/php-lib-rest-plugin-indieauth.svg?branch=master)](https://travis-ci.org/fkooman/php-lib-rest-plugin-indieauth)

# Introduction
This plugin enables one to use IndieAuth authentication with `fkooman/rest`.

See `example/indieauth.php` for an example on how to use this in your 
application.

# API
The plugin works by registering three endpoints under `/indieauth`:

* `/indieauth/auth` 
* `/indieauth/callback`
* `/indieauth/logout`

So if your application is running under `https://www.example.org/foo`, the 
`/indieauth/auth` endpoint becomes 
`https://www.example.org/foo/indieauth/auth`.

The `/indieauth/auth` endpoint accepts a `POST` containing the `me` parameter 
with the user's homepage. It can be used for example from the app by showing 
the user a form to authenticate:

    <form method="post" action="indieauth/auth">
        https://<input type="text" name="me" placeholder="example.org" required>
        <input type="submit" value="Sign In">
    </form>

The `/indieauth/auth` endpoint will take care of validating the URL, 
determining "Distributed IndieAuth" support and normalizing the URL: 
adding `https://` to the start if needed, adding a default path `/` if it is 
missing or converting the host part to lowercase.

Then it will talk to the IndieAuth compatible server and redirect the browser
to `/indieauth/callback` where the token is received and validated. 

Next the browser is redirected to the location specified in the contructor 
when loading the `IndieAuthAuthentication` class. See the example for more 
information. Soon this will be moved to the form POST, and not the constructor.


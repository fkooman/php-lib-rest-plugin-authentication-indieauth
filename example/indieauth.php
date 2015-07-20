<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
require_once dirname(__DIR__).'/vendor/autoload.php';

use fkooman\Rest\Service;
use fkooman\Http\Request;
use fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication;
use fkooman\Rest\Plugin\Authentication\IndieAuth\IndieInfo;
use GuzzleHttp\Client;

$service = new Service();

// use discovery by default, fall back to IndieCert (https://indiecert.net/auth)
$indieAuth = new IndieAuthAuthentication();

// in case no session is active yet, redirect to '/'
$indieAuth->setUnauthorizedRedirectUri('/');

$client = new Client(
    array(
        'defaults' => array(
            // DO NOT set 'verify => false' in actual deployments!
            'verify' => false,
            'timeout' => 10,
        ),
    )
);
$indieAuth->setClient($client);

// use discovery by default, fall back to IndieAuth (https://indieauth.com/auth)
//$indieAuth = new IndieAuthAuthentication('https://indieauth.com/auth');

// disable discovery (i.e. "Distributed IndieAuth")
// $indieAuth->setDiscovery(false);

$service->getPluginRegistry()->registerDefaultPlugin($indieAuth);

$service->get(
    '/',
    function (Request $request) {
        // Show Sign In form;  POST to '_indieauth/auth' endpoint which is registered by the IndieAuth plugin
        $output = '<html><head></style></head><body><h1>Sign In</h1>';

        $output .= '<h2>Authentication Only</h2><form method="post" action="_indieauth/auth">https://<input type="text" name="me" placeholder="example.org" required><input type="hidden" name="redirect_to" value="/success"><input type="submit" value="Sign In"></form>';

        $output .= '</body></html>';

        return $output;
    },
    array(
        // To view the index page, no authentication is required
        'fkooman\Rest\Plugin\Authentication\IndieAuth\IndieAuthAuthentication' => array('enabled' => false),
    )
);

// To view the "success" page, authentication is required
$service->get(
    '/success',
    function (IndieInfo $u) {
        $output = sprintf(
            '<html><head></head><body><h1>Hello</h1><table><tr><th>User ID</th><td>%s</td></tr></table><form method="post" action="_indieauth/logout"><input type="submit" value="Logout"></form></body></html>',
            $u->getUserId()
        );

        return $output;
    }
);

$service->run()->send();

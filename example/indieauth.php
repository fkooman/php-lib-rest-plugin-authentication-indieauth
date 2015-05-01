<?php

/**
* Copyright 2015 François Kooman <fkooman@tuxed.net>
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
use fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication;
use fkooman\Rest\Plugin\IndieAuth\IndieInfo;
use GuzzleHttp\Client;

try {
    $service = new Service();

    // use discovery by default, fall back to IndieCert (https://indiecert.net/auth)
    $indieAuth = new IndieAuthAuthentication();
    
    // in case no session is active yet, redirect to '/'
    $indieAuth->setUnauthorizedRedirectUri('/');

    $client = new Client(
        array(
            'defaults' => array(
                'verify' => false,
                'timeout' => 10
            )
        )
    );
    $indieAuth->setClient($client);

    // use discovery by default, fall back to IndieAuth (https://indieauth.com/auth)
    //$indieAuth = new IndieAuthAuthentication('https://indieauth.com/auth');

    // disable discovery (i.e. "Distributed IndieAuth")
    // $indieAuth->setDiscovery(false);

    $service->registerOnMatchPlugin($indieAuth);

    $service->get(
        '/',
        function (Request $request) {
            // Show Sign In form;  POST to 'indieauth/auth' endpoint which is registered by the IndieAuth plugin
            $output = '<html><head></style></head><body><h1>Sign In</h1>';

            // without requesting access token (no scope)
            $output .= '<h2>Authentication Only</h2><form method="post" action="indieauth/auth">https://<input type="text" name="me" placeholder="example.org" required><input type="hidden" name="redirect_to" value="/success"><input type="submit" value="Sign In"></form>';

            // with requesting access token (scope)
            $output .= '<h2>Authentication &amp; Token</h2><form method="post" action="indieauth/auth">https://<input type="text" name="me" placeholder="example.org" required><input type="text" name="scope" value="post"><input type="hidden" name="redirect_to" value="/success"><input type="submit" value="Sign In"></form>';

            $output .= '</body></html>';
            return $output;
        },
        array(
            // To view the index page, no authentication is required
            'skipPlugins' => array(
                'fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'
             )
        )
    );

    // To view the "success" page, authentication is required
    $service->get(
        '/success',
        function (IndieInfo $u) {
            return sprintf(
                '<html><head></head><body><h1>Hello</h1><table><tr><th>User ID</th><td>%s</td></tr><th>Access Token</th><td>%s</td></tr><tr><th>Scope</th><td>%s</td></tr></table><p><a href="indieauth/logout">logout</a></p></body></html>',
                $u->getUserId(), $u->getAccessToken(), $u->getScope()
            );
        }
    );

    $service->run()->sendResponse();
} catch (Exception $e) {
    // in case en error occurred we display a HTML page with more details
    Service::handleException($e)->sendResponse();
}

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
use fkooman\Rest\Plugin\UserInfo;

try {
    $service = new Service();
    $service->registerOnMatchPlugin(
        new IndieAuthAuthentication(
            '/welcome'
        )
    );

    $service->get(
        '/',
        function (Request $request) {
            // show sign in form, post to 'indieauth/auth' endpoint as registered by plugin
            return '<html><head></head><body><h1>Sign In</h1><form method="post" action="indieauth/auth"><input type="text" name="me" placeholder="yourdomain.com"><input type="submit" value="Sign In"></form></body></html>';
        },
        // no authentication needed on welcome page...
        array(
            'skipPlugins' => array(
                'fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'
             )
        )
    );

    $service->get(
        '/welcome',
        function (UserInfo $u) {
            // here we do need to be authenticated...
            return sprintf('<html><head></head><body><h1>Hello</h1><p>Hello %s</p></body></html>', $u->getUserId());
        }
    );

    $service->run()->sendResponse();
} catch (Exception $e) {
    Service::handleException($e)->sendResponse();
}

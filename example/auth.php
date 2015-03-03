<?php

/**
* Copyright 2014 François Kooman <fkooman@tuxed.net>
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
use fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication;
use fkooman\Rest\Plugin\UserInfo;

$service = new Service();
$service->registerOnMatchPlugin(
    new IndieCertAuthentication(
        '/welcome'
    )
);

$service->get(
    '/',
    function (Request $request) {
        // show sign in form, post to 'indiecert/auth' endpoint as registered by plugin
        return '<html><head></head><body><h1>Sign In</h1><form method="post" action="indiecert/auth"><input type="text" name="me" placeholder="yourdomain.com"><input type="submit" value="Sign In"></form></body></html>';
    },
    // no authentication needed on welcome page...
    array('fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication')
);

$service->get(
    '/welcome',
    function (UserInfo $u) {
        // here we do need to be authenticated...
        return sprintf('Hello %s', $u->getUserId());
    }
);

$service->run()->sendResponse();

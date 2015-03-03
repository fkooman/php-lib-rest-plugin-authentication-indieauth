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

namespace fkooman\Rest\Plugin\IndieCert;

use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\ServicePluginInterface;
use fkooman\Rest\Plugin\UserInfo;
use GuzzleHttp\Client;

class IndieCertAuthentication implements ServicePluginInterface
{
    /** @var fkooman\Http\Session */
    private $session;

    public function __construct(Service $service, Session $session = null, Client $client = null, $authUri = 'https://indiecert.net/auth', $verifyUri = 'https://indiecert.net/verify')
    {
        if (null === $session) {
            $session = new Session('IndieCert');
        }
        $this->session = $session;

        if (null === $client) {
            $client = new Client();
        }

        $service->post(
            'indiecert/auth',
            function (Request $request) use ($session, $authUri) {
                $me = $request->getPostParameter('me');
                $redirectUri = $request->getRequestUri()->getBaseUri() . $request->getAppRoot() . 'indiecert_callback';
                $stateValue = '12345';
                $session->setValue('state', $stateValue);
                $session->setValue('redirect_uri', $redirectUri);

                $fullAuthUri = sprintf('%s?me=%s&redirect_uri=%s&state=%s', $authUri, $me, $redirectUri, $stateValue);

                return new RedirectResponse($fullAuthUri, 302);
            },
            array('fkooman\Rest\Plugin\IndieCertAuthentication')
        );

        $service->get(
            'indiecert/callback',
            function (Request $request) use ($session, $client, $verifyUri) {
                if ($session->getKey('state') !== $request->getQueryParameter('state')) {
                    throw new BadRequestException('non matching state');
                }
                $code = $request->getQueryParameter('code');
                $verifyRequest = $client->createRequest(
                    'POST',
                    $verifyUri,
                    array(
                        'body' => array(
                            'code' => $request->getQueryParameter('code'),
                            'redirect_uri' => $session->getKey('redirect_uri')
                        )
                    )
                );
                $verifyResponse = $client->send($verifyRequest)->json();
                $session->setKey('me', $verifyResponse['me']);

                // FIXME: redirect to a page where you need to be authenticated...
                return new RedirectResponse($request->getRequestUri()->getBaseUri() . $request->getAppRoot() . 'authenticated');
            },
            array('fkooman\Rest\Plugin\IndieCertAuthentication')
        );
    }

    public function execute(Request $request)
    {
        $userId = $this->session->getKey('me');
        if (null === $userId) {
            throw new UnauthorizedException('not authenticated', 'no authenticated session', 'IndieCert');
        }

        return new UserInfo($userId);
    }
}

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
use fkooman\Rest\Service;
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
    
    public function __construct(Service $service, $redirectTo = null, $authUri = 'https://indiecert.net/auth', $verifyUri = 'https://indiecert.net/verify', Session $session = null, Client $client = null, IO $io = null)
    {
        if (null === $session) {
            $session = new Session('IndieCert');
        }
        $this->session = $session;
        if (null === $client) {
            $client = new Client();
        }
        if (null === $io) {
            $io = new IO();
        }

        $service->post(
            '/indiecert/auth',
            function (Request $request) use ($session, $io, $authUri, $redirectTo) {
                $me = $request->getPostParameter('me');
                $redirectUri = $request->getRequestUri()->getBaseUri() . $request->getAppRoot() . 'indiecert/callback';

                if (null === $redirectTo) {
                    $redirectTo = $request->getHeader('HTTP_REFERER');
                }

                if (0 === strpos($redirectTo, '/')) {
                    // assume URI relative to appRoot
                    $redirectTo = $request->getRequestUri()->getBaseUri() . $request->getAppRoot() . substr($redirectTo, 1);
                }

                $stateValue = $io->getRandomHex();
                $session->setValue('state', $stateValue);
                $session->setValue('redirect_uri', $redirectUri);
                $session->setValue('redirect_to', $redirectTo);

                $fullAuthUri = sprintf('%s?me=%s&redirect_uri=%s&state=%s', $authUri, $me, $redirectUri, $stateValue);

                return new RedirectResponse($fullAuthUri, 302);
            },
            array('fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication')
        );

        $service->get(
            '/indiecert/callback',
            function (Request $request) use ($session, $client, $verifyUri) {
                $sessionState = $session->getValue('state');
                if (null === $sessionState) {
                    throw new BadRequestException('no session state available');
                }
                if ($sessionState !== $request->getQueryParameter('state')) {
                    throw new BadRequestException('non matching state');
                }
                $verifyRequest = $client->createRequest(
                    'POST',
                    $verifyUri,
                    array(
                        'body' => array(
                            'code' => $request->getQueryParameter('code'),
                            'redirect_uri' => $session->getValue('redirect_uri')
                        )
                    )
                );
                $verifyResponse = $client->send($verifyRequest)->json();
                $session->setValue('me', $verifyResponse['me']);

                $redirectTo = $session->getValue('redirect_to');

                return new RedirectResponse($redirectTo, 302);
            },
            array('fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication')
        );
    }

    public function execute(Request $request)
    {
        $userId = $this->session->getValue('me');
        if (null === $userId) {
            throw new UnauthorizedException('not authenticated', 'no authenticated session', 'IndieCert');
        }

        return new UserInfo($userId);
    }
}

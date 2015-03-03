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
    /** @var string */
    private $redirectTo;

    /** @var string */
    private $authUri;

    /** @var string */
    private $verifyUri;

    /** @var fkooman\Http\Session */
    private $session;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\Rest\Plugin\IndieCert\IO */
    private $io;

    public function __construct($redirectTo = null, $authUri = null, $verifyUri = null)
    {
        $this->redirectTo = $redirectTo;
        if (null === $authUri) {
            $authUri = 'https://indiecert.net/auth';
        }
        $this->authUri = $authUri;
        if (null === $verifyUri) {
            $verifyUri = 'https://indiecert.net/verify';
        }
        $this->verifyUri = $verifyUri;
    }

    public function setSession(Session $session)
    {
        $this->session = $session;
    }

    public function setClient(Client $client)
    {
        $this->client = $client;
    }

    public function setIO(IO $io)
    {
        $this->io = $io;
    }

    public function init(Service $service)
    {
        if (null === $this->session) {
            $this->session = new Session('IndieCert');
        }
        if (null === $this->client) {
            $this->client = new Client();
        }
        if (null === $this->io) {
            $this->io = new IO();
        }

        $service->post(
            '/indiecert/auth',
            function (Request $request) {
                $me = $request->getPostParameter('me');
                $redirectUri = $request->getAppRoot() . 'indiecert/callback';

                if (null === $this->redirectTo) {
                    $this->redirectTo = $request->getHeader('HTTP_REFERER');
                }

                if (0 === strpos($this->redirectTo, '/')) {
                    // assume URI relative to appRoot
                    $this->redirectTo = $request->getAppRoot() . substr($this->redirectTo, 1);
                }

                $stateValue = $this->io->getRandomHex();
                $this->session->setValue('state', $stateValue);
                $this->session->setValue('redirect_uri', $redirectUri);
                $this->session->setValue('redirect_to', $this->redirectTo);

                $fullAuthUri = sprintf('%s?me=%s&redirect_uri=%s&state=%s', $this->authUri, $me, $redirectUri, $stateValue);

                return new RedirectResponse($fullAuthUri, 302);
            },
            array('fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication')
        );

        $service->get(
            '/indiecert/callback',
            function (Request $request) {
                $sessionState = $this->session->getValue('state');
                if (null === $sessionState) {
                    throw new BadRequestException('no session state available');
                }
                if ($sessionState !== $request->getQueryParameter('state')) {
                    throw new BadRequestException('non matching state');
                }
                $verifyRequest = $this->client->createRequest(
                    'POST',
                    $this->verifyUri,
                    array(
                        'body' => array(
                            'code' => $request->getQueryParameter('code'),
                            'redirect_uri' => $this->session->getValue('redirect_uri')
                        )
                    )
                );
                $verifyResponse = $this->client->send($verifyRequest)->json();
                $this->session->setValue('me', $verifyResponse['me']);

                $redirectTo = $this->session->getValue('redirect_to');

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

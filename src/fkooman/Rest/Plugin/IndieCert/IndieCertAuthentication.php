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
use fkooman\Http\Uri;
use InvalidArgumentException;

class IndieCertAuthentication implements ServicePluginInterface
{
    /** @var string */
    private $redirectTo;

    /** @var string */
    private $authUri;

    /** @var fkooman\Http\Session */
    private $session;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\Rest\Plugin\IndieCert\IO */
    private $io;

    public function __construct($redirectTo = null, $authUri = null)
    {
        $this->redirectTo = $redirectTo;
        if (null === $authUri) {
            $authUri = 'https://indiecert.net/auth';
        }
        $this->authUri = $authUri;
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
                $me = $this->validateMe($request->getPostParameter('me'));
                $redirectUri = $request->getAbsRoot() . 'indiecert/callback';

                if (null === $this->redirectTo) {
                    // no redirectTo specifed, use HTTP_REFERER
                    $referrer = $request->getHeader('HTTP_REFERER');
                    if (0 !== strpos($referrer, $request->getAbsRoot())) {
                        throw new BadRequestException('referrer URL wants to redirect outside application');
                    }
                    $this->redirectTo = $referrer;
                } else {
                    // redirectTo specified, check if it is relative or absolute
                    if (0 === strpos($this->redirectTo, '/')) {
                        // assume URI relative to absRoot
                        $this->redirectTo = $request->getAbsRoot() . substr($this->redirectTo, 1);
                    }
                }

                $stateValue = $this->io->getRandomHex();
                $this->session->deleteKey('me');
                $this->session->setValue('state', $stateValue);
                $this->session->setValue('redirect_uri', $redirectUri);
                $this->session->setValue('redirect_to', $this->redirectTo);

                $fullAuthUri = sprintf('%s?me=%s&redirect_uri=%s&state=%s', $this->authUri, $me, $redirectUri, $stateValue);

                return new RedirectResponse($fullAuthUri, 302);
            },
            array(
                'skipPlugins' => array(
                    'fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication'
                )
            )
        );

        $service->get(
            '/indiecert/callback',
            function (Request $request) {
                $sessionState = $this->session->getValue('state');
                $sessionRedirectUri = $this->session->getValue('redirect_uri');
                $redirectTo = $this->session->getValue('redirect_to');

                $queryState = $this->validateState($request->getQueryParameter('state'));
                $queryCode = $this->validateCode($request->getQueryParameter('code'));

                if (null === $sessionState) {
                    throw new BadRequestException('no session state available');
                }
                if ($sessionState !== $queryState) {
                    throw new BadRequestException('non matching state');
                }
                $verifyRequest = $this->client->createRequest(
                    'POST',
                    $this->authUri,
                    array(
                        'headers' => array('Accept' => 'application/json'),
                        'body' => array(
                            'code' => $queryCode,
                            'redirect_uri' => $sessionRedirectUri
                        )
                    )
                );
                $verifyResponse = $this->client->send($verifyRequest)->json();
                $this->session->setValue('me', $verifyResponse['me']);

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'skipPlugins' => array(
                    'fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication'
                )
            )
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

    private function validateState($state)
    {
        if (null === $state) {
            throw new BadRequestException('missing parameter "state"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $state)) {
            throw new BadRequestException('"state" contains invalid characters');
        }

        return $state;
    }

    private function validateCode($code)
    {
        if (null === $code) {
            throw new BadRequestException('missing parameter "code"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $code)) {
            throw new BadRequestException('"code" contains invalid characters');
        }

        return $code;
    }

    private function validateMe($me)
    {
        if (null === $me) {
            throw new BadRequestException('missing parameter "me"');
        }
        if (0 !== strpos($me, 'http')) {
            $me = sprintf('https://%s', $me);
        }
        try {
            $uriObj = new Uri($me);
            if ('https' !== $uriObj->getScheme()) {
                throw new BadRequestException('"me" must be https uri');
            }
            if (null !== $uriObj->getQuery()) {
                throw new BadRequestException('"me" cannot contain query parameters');
            }
            if (null !== $uriObj->getFragment()) {
                throw new BadRequestException('"me" cannot contain fragment');
            }
            // if we have no path add '/'
            if (null === $uriObj->getPath()) {
                $me .= '/';
            }
            
            return $me;
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('"me" is an invalid uri');
        }
    }
}

<?php

/**
 * Copyright 2014 François Kooman <fkooman@tuxed.net>.
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
namespace fkooman\Rest\Plugin\IndieAuth;

use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\ServicePluginInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use RuntimeException;

class IndieAuthAuthentication implements ServicePluginInterface
{
    /** @var string */
    private $authUri;

    /** @var string */
    private $tokenUri;

    /** @var string */
    private $unauthorizedRedirectUri;

    /** @var bool */
    private $discoveryEnabled;

    /** @var fkooman\Http\Session */
    private $session;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\Rest\Plugin\IndieAuth\IO */
    private $io;

    public function __construct($authUri = null, $tokenUri = null)
    {
        if (null === $authUri) {
            $authUri = 'https://indiecert.net/auth';
        }
        $this->authUri = $authUri;
        if (null === $tokenUri) {
            $tokenUri = 'https://indiecert.net/token';
        }
        $this->tokenUri = $tokenUri;
        $this->unauthorizedRedirectUri = null;
        $this->discoveryEnabled = true;
    }

    public function setUnauthorizedRedirectUri($unauthorizedRedirectUri)
    {
        $this->unauthorizedRedirectUri = $unauthorizedRedirectUri;
    }

    public function setDiscovery($discoveryEnabled)
    {
        $this->discoveryEnabled = (bool) $discoveryEnabled;
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
            $this->session = new Session('IndieAuth');
        }
        if (null === $this->client) {
            $this->client = new Client();
        }
        if (null === $this->io) {
            $this->io = new IO();
        }

        $service->post(
            '/indieauth/auth',
            function (Request $request) {
                $this->session->delete('me');
                $this->session->delete('access_token');
                $this->session->delete('scope');
                $this->session->delete('auth');

                $me = InputValidation::validateMe($request->getPostParameter('me'));
                $scope = InputValidation::validateScope($request->getPostParameter('scope'));

                // if discovery is enabled, we try find the authUri and tokenUri
                if ($this->discoveryEnabled) {
                    $discovery = new Discovery($this->client);
                    $discoveryResponse = $discovery->discover($me);
                    if (null !== $discoveryResponse->getAuthorizationEndpoint()) {
                        $this->authUri = $discoveryResponse->getAuthorizationEndpoint();
                    }
                    if (null !== $discoveryResponse->getTokenEndpoint()) {
                        $this->tokenUri = $discoveryResponse->getTokenEndpoint();
                    }
                }

                $clientId = $request->getUrl()->getRootUrl();
                $redirectUri = $request->getUrl()->getRootUrl().'indieauth/callback';
                $stateValue = $this->io->getRandomHex();
                $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getPostParameter('redirect_to'));

                $authSession = array(
                    'auth_uri' => $this->authUri,
                    'token_uri' => $this->tokenUri,
                    'me' => $me,
                    'state' => $stateValue,
                    'redirect_to' => $redirectTo,
                );
                if (null !== $scope) {
                    $authSession['scope'] = $scope;
                }

                $this->session->set('auth', $authSession);

                $authUriParams = array(
                    'client_id' => $clientId,
                    'response_type' => 'code',
                    'me' => $me,
                    'redirect_uri' => $redirectUri,
                    'state' => $stateValue,
                );

                if (null !== $scope) {
                    $authUriParams['scope'] = $scope;
                }

                $fullAuthUri = sprintf(
                    '%s?%s',
                    $this->authUri,
                    http_build_query($authUriParams, '', '&')
                );

                return new RedirectResponse($fullAuthUri, 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
                'fkooman\Rest\Plugin\ReferrerCheckPlugin' => array('enabled' => true),
            )
        );

        $service->get(
            '/indieauth/callback',
            function (Request $request) {
                $authSession = $this->session->get('auth');

                if (!is_array($authSession)) {
                    throw new BadRequestException('no session available');
                }

                $queryState = InputValidation::validateState($request->getUrl()->getQueryParameter('state'));
                $queryCode = InputValidation::validateCode($request->getUrl()->getQueryParameter('code'));

                if (null === $authSession['state']) {
                    throw new BadRequestException('no session state available');
                }
                if ($authSession['state'] !== $queryState) {
                    throw new BadRequestException('non matching state');
                }
                $verifyRequest = $this->client->createRequest(
                    'POST',
                    $authSession['auth_uri'],
                    array(
                        'headers' => array('Accept' => 'application/json'),
                        'body' => array(
                            'client_id' => $request->getUrl()->getRootUrl(),
                            // https://github.com/aaronpk/IndieAuth.com/issues/81
                            // "state parameter required on verify POST"
                            'grant_type' => 'authorization_code',
                            'state' => $queryState,
                            'code' => $queryCode,
                            'redirect_uri' => $request->getUrl()->getRootUrl().'indieauth/callback',
                        ),
                    )
                );

                $responseData = $this->decodeResponse($this->client->send($verifyRequest));

                if (!is_array($responseData) || !array_key_exists('me', $responseData)) {
                    throw new RuntimeException('me field not found in response');
                }

                if ($authSession['me'] !== $responseData['me']) {
                    throw new RuntimeException(
                        sprintf(
                            'received "me" (%s) different from expected "me" (%s)',
                            $responseData['me'],
                            $authSession['me']
                        )
                    );
                }
                $this->session->set('me', $responseData['me']);

                // if we requested a scope, we also want an access token
                if (array_key_exists('scope', $authSession) && null !== $authSession['scope']) {
                    $verifyRequest = $this->client->createRequest(
                        'POST',
                        $authSession['token_uri'],
                        array(
                            'headers' => array('Accept' => 'application/json'),
                            'body' => array(
                                'client_id' => $request->getUrl()->getRootUrl(),
                                // https://github.com/aaronpk/IndieAuth.com/issues/81
                                // "state parameter required on verify POST"
                                'grant_type' => 'authorization_code',
                                'state' => $queryState,
                                'code' => $queryCode,
                                'redirect_uri' => $request->getUrl()->getRootUrl().'indieauth/callback',
                            ),
                        )
                    );

                    $responseData = $this->decodeResponse($this->client->send($verifyRequest));

                    if (!is_array($responseData) || !array_key_exists('me', $responseData)) {
                        throw new RuntimeException('me field not found in response');
                    }

                    if ($authSession['me'] !== $responseData['me']) {
                        throw new RuntimeException(
                            sprintf(
                                'received "me" (%s) different from expected "me" (%s)',
                                $responseData['me'],
                                $authSession['me']
                            )
                        );
                    }
                    $this->session->set('access_token', $responseData['access_token']);
                    $this->session->set('scope', $responseData['scope']);
                }

                $this->session->delete('auth');

                return new RedirectResponse($authSession['redirect_to'], 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
            )
        );

        $service->post(
            '/indieauth/logout',
            function (Request $request) {
                $this->session->destroy();
                $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getUrl()->getQueryParameter('redirect_to'));

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
                'fkooman\Rest\Plugin\ReferrerCheckPlugin' => array('enabled' => true),
            )
        );
    }

    public function execute(Request $request, array $routeConfig)
    {
        $userId = $this->session->get('me');
        $accessToken = $this->session->get('access_token');
        $scope = $this->session->get('scope');

        if (null === $userId) {
            // check if authentication is required...
            if (array_key_exists('requireAuth', $routeConfig)) {
                if (!$routeConfig['requireAuth']) {
                    return false;
                }
            }

            if (null !== $this->unauthorizedRedirectUri) {
                $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $this->unauthorizedRedirectUri);

                return new RedirectResponse(
                    sprintf(
                        '%s?redirect_to=%s',
                        $redirectTo,
                        // FIXME: do we need to remove query/fragment?
                        $request->getUrl()->toString()
                    ),
                    302
                );
            }

            throw new UnauthorizedException('not authenticated', 'no authenticated session', 'IndieAuth');
        }

        return new IndieInfo($userId, $accessToken, $scope);
    }

    private function decodeResponse(Response $response)
    {
        $contentType = $response->getHeader('Content-Type');

        if (false !== strpos($contentType, 'application/json')) {
            return $response->json();
        }

        if (false !== strpos($contentType, 'application/x-www-form-urlencoded')) {
            $verifyData = array();
            $responseBody = strval($response->getBody());
            parse_str($responseBody, $verifyData);

            return $verifyData;
        }

        throw new RuntimeException('invalid content type from verify endpoint');
    }
}

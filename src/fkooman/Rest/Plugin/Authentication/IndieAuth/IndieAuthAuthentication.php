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

namespace fkooman\Rest\Plugin\Authentication\IndieAuth;

use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\IO\IO;
use fkooman\Rest\Service;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Message\ResponseInterface;
use RuntimeException;

class IndieAuthAuthentication implements AuthenticationPluginInterface
{
    /** @var string */
    private $authUri;

    /**
     * The URL to redirect to if no authentication is attempted.
     *
     * @var string
     */
    private $unauthorizedRedirectUri;

    /** @var bool */
    private $discoveryEnabled;

    /** @var \fkooman\Http\Session */
    private $session;

    /** @var \GuzzleHttp\Client */
    private $client;

    /** @var \fkooman\IO\IO */
    private $io;

    /** @var array */
    private $authParams;

    public function __construct($authUri = null, array $authParams = array())
    {
        if (null === $authUri) {
            $authUri = 'https://indiecert.net/auth';
        }
        $this->authUri = $authUri;

        $this->unauthorizedRedirectUri = null;
        $this->discoveryEnabled = true;

        if (!array_key_exists('realm', $authParams)) {
            $authParams['realm'] = 'Protected Resource';
        }
        $this->authParams = $authParams;
    }

    public function getScheme()
    {
        return 'IndieAuth';
    }

    public function getAuthParams()
    {
        return $this->authParams;
    }

    public function isAttempt(Request $request)
    {
        // if the correct session parameters are set and the IndieAuth 
        // authentication already succeeded
        if (null !== $this->session->get('me')) {
            return true;
        }

        if (null !== $this->unauthorizedRedirectUri) {
            // no (direct) attempt, but we have the ability to redirect the 
            // user to a login page, so we define this as there being an 
            // attempt...
            return true;
        }

        return false;
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
            '/_indieauth/auth',
            function (Request $request) {
                // delete possibly stale auth session
                $this->session->delete('auth');

                // new attempt will override current 'me'
                $this->session->delete('me');

                $me = InputValidation::validateMe($request->getPostParameter('me'));

                // if discovery is enabled, we try find the authUri
                if ($this->discoveryEnabled) {
                    $discovery = new Discovery($this->client);
                    $discoveryResponse = $discovery->discover($me);
                    if (null !== $discoveryResponse->getAuthorizationEndpoint()) {
                        // FIXME: validate authorization_endpoint?
                        $this->authUri = $discoveryResponse->getAuthorizationEndpoint();
                    }
                }

                $clientId = $request->getUrl()->getRootUrl();
                $stateValue = $this->io->getRandom();
                $redirectUri = $request->getUrl()->getRootUrl().'_indieauth/callback';
                $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getPostParameter('redirect_to'));

                $authSession = array(
                    'client_id' => $clientId,
                    'auth_uri' => $this->authUri,
                    'me' => $me,
                    'state' => $stateValue,
                    'redirect_uri' => $redirectUri,
                    'redirect_to' => $redirectTo,
                );
                $this->session->set('auth', $authSession);

                $authUriParams = array(
                    # FIXME: add also user_hint or similar OpenID Connect parameter
                    'client_id' => $clientId,
                    'response_type' => 'code',
                    'me' => $me,
                    'redirect_uri' => $redirectUri,
                    'state' => $stateValue,
                );

                $fullAuthUri = sprintf(
                    '%s?%s',
                    $this->authUri,
                    http_build_query($authUriParams, '', '&')
                );

                return new RedirectResponse($fullAuthUri, 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );

        $service->get(
            '/_indieauth/callback',
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
                            'client_id' => $authSession['client_id'],
                            'grant_type' => 'authorization_code',
                            // https://github.com/aaronpk/IndieAuth.com/issues/81
                            // "state parameter required on verify POST"
                            'state' => $queryState,
                            'code' => $queryCode,
                            'redirect_uri' => $authSession['redirect_uri'],
                        ),
                    )
                );

                $responseData = $this->decodeResponse($this->client->send($verifyRequest));

                if (!is_array($responseData) || !array_key_exists('me', $responseData)) {
                    throw new RuntimeException('"me" field not found in response');
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
                $this->session->delete('auth');

                return new RedirectResponse($authSession['redirect_to'], 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );

        $service->post(
            '/_indieauth/logout',
            function (Request $request) {
                $this->session->destroy();
                $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $request->getUrl()->getQueryParameter('redirect_to'));

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                __CLASS__ => array('enabled' => false),
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array('enabled' => false),
            )
        );
    }

    public function execute(Request $request, array $routeConfig)
    {
        $userId = $this->session->get('me');

        if (null !== $userId) {
            return new IndieInfo($userId);
        }

        // check if authentication is required...
        if (array_key_exists('require', $routeConfig)) {
            if (!$routeConfig['require']) {
                return;
            }
        }

        if (null !== $this->unauthorizedRedirectUri) {
            // we have the ability to redirect the user to a login page, do 
            // that! 
            $redirectTo = InputValidation::validateRedirectTo($request->getUrl()->getRootUrl(), $this->unauthorizedRedirectUri);

            $querySeparator = false === strpos($redirectTo, '?') ? '?' : '&';

            // add the "me" parameter to the redirectTo URL if it is set
            $me = $request->getUrl()->getQueryParameter('me');
            if (null !== $me) {
                $redirectTo = sprintf('%s%sme=%s', $redirectTo, $querySeparator, $me);
                $querySeparator = '&';
            }

            return new RedirectResponse(
                sprintf(
                    '%s%sredirect_to=%s',
                    $redirectTo,
                    $querySeparator,
                    urlencode($request->getUrl()->toString())
                ),
                302
            );
        }

        $e = new UnauthorizedException(
            'no_credentials',
            'no authenticated session'
        );
        $e->addScheme('IndieAuth', $this->authParams);
        throw $e;
    }

    private function decodeResponse(ResponseInterface $response)
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

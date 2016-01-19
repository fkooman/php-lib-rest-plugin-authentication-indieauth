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

use fkooman\Http\SessionInterface;
use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\IO\IO;
use fkooman\Http\Response;
use fkooman\Rest\Service;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Rest\Plugin\Authentication\AuthenticationPluginInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Message\ResponseInterface;
use RuntimeException;
use fkooman\Tpl\TemplateManagerInterface;

class IndieAuthAuthentication implements AuthenticationPluginInterface
{
    /** @var \fkooman\Tpl\TemplateManagerInterface */
    private $templateManager;

    /** @var \GuzzleHttp\Client */
    private $client;

    /** @var \fkooman\Http\SessionInterface */
    private $session;

    /** @var \fkooman\IO\IO */
    private $io;

    /** @var string */
    private $authUri;

    public function __construct(TemplateManagerInterface $templateManager, Client $client = null, SessionInterface $session = null, IO $io = null)
    {
        $this->templateManager = $templateManager;

        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;

        if (null === $session) {
            $session = new Session('indieauth');
        }
        $this->session = $session;

        if (null === $io) {
            $io = new IO();
        }
        $this->io = $io;

        $this->authUri = null;
    }

    /**
     * Set the URL to use to authenticate the user. Doing this will disable 
     * discovery.
     */
    public function setAuthUri($authUri)
    {
        $this->authUri = $authUri;
    }

    public function isAuthenticated(Request $request)
    {
        $authIndieAuthMe = $this->session->get('_auth_indieauth_me');
        if (is_null($authIndieAuthMe)) {
            return false;
        }

        return new IndieInfo($authIndieAuthMe);
    }

    public function init(Service $service)
    {
        $service->post(
            '/_auth/indieauth/auth',
            function (Request $request) {
                $this->session->delete('_auth_indieauth_me');
                $this->session->delete('_auth_indieauth_session');

                $me = InputValidation::validateMe($request->getPostParameter('me'));

                if (is_null($this->authUri)) {
                    // no authUri set, we use discovery
                    $discovery = new Discovery($this->client);
                    $discoveryResponse = $discovery->discover($me);
                    if (null !== $discoveryResponse->getAuthorizationEndpoint()) {
                        // XXX: validate authorization_endpoint
                        $this->authUri = $discoveryResponse->getAuthorizationEndpoint();
                    }
                }

                $clientId = $request->getUrl()->getRootUrl();
                $stateValue = $this->io->getRandom();
                $redirectUri = $request->getUrl()->getRootUrl().'_auth/indieauth/callback';
                $redirectTo = self::getRedirectTo($request);

                $authSession = array(
                    'client_id' => $clientId,
                    'auth_uri' => $this->authUri,
                    'me' => $me,
                    'state' => $stateValue,
                    'redirect_uri' => $redirectUri,
                    'redirect_to' => $redirectTo,
                );
                $this->session->set('_auth_indieauth_session', $authSession);

                $authUriParams = array(
                    # XXX: add also user_hint or similar OpenID Connect parameter
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
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );

        $service->get(
            '/_auth/indieauth/callback',
            function (Request $request) {
                $authSession = $this->session->get('_auth_indieauth_session');

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

                $responseData = self::decodeResponse($this->client->send($verifyRequest));

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

                $this->session->set('_auth_indieauth_me', $responseData['me']);
                $this->session->delete('_auth_indieauth_session');

                return new RedirectResponse($authSession['redirect_to'], 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );

        $service->post(
            '/_auth/indieauth/logout',
            function (Request $request) {
                $this->session->destroy();
                $redirectTo = self::getRedirectTo($request);

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'fkooman\Rest\Plugin\Authentication\AuthenticationPlugin' => array(
                    'enabled' => false,
                ),
            )
        );
    }

    public function requestAuthentication(Request $request)
    {
        $response = new Response(200);
        $response->setHeader('X-Frame-Options', 'DENY');
        $response->setHeader('Content-Security-Policy', "default-src 'self'");
        $response->setBody(
            $this->templateManager->render(
                'indieAuthAuth',
                array(
                    'login_hint' => $request->getUrl()->getQueryParameter('login_hint'),
                    '_auth_indieauth_root_url' => $request->getUrl()->getRootUrl(),
                )
            )
        );

        return $response;
    }

    private static function decodeResponse(ResponseInterface $response)
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

        throw new RuntimeException('unexpected content type from verify endpoint');
    }

    private static function getRedirectTo(Request $request)
    {
        $redirectTo = $request->getPostParameter('redirect_to');
        if (is_null($redirectTo)) {
            $redirectTo = $request->getUrl()->getRootUrl();
        }
        InputValidation::validateRedirectTo($redirectTo);

        return $redirectTo;
    }
}

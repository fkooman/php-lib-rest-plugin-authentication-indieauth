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

namespace fkooman\Rest\Plugin\IndieAuth;

use fkooman\Http\Session;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Http\RedirectResponse;
use fkooman\Http\Exception\BadRequestException;
use fkooman\Http\Exception\UnauthorizedException;
use fkooman\Rest\ServicePluginInterface;
use fkooman\Rest\Plugin\UserInfo;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use fkooman\Http\Uri;
use InvalidArgumentException;
use DomDocument;
use RuntimeException;

class IndieAuthAuthentication implements ServicePluginInterface
{
    /** @var string */
    private $redirectTo;

    /** @var string */
    private $authUri;

    /** @var boolean */
    private $discoveryEnabled;

    /** @var fkooman\Http\Session */
    private $session;

    /** @var GuzzleHttp\Client */
    private $client;

    /** @var fkooman\Rest\Plugin\IndieAuth\IO */
    private $io;

    public function __construct($redirectTo = null, $authUri = null)
    {
        $this->redirectTo = $redirectTo;
        if (null === $authUri) {
            $authUri = 'https://indiecert.net/auth';
        }
        $this->authUri = $authUri;
        $this->discoveryEnabled = true;
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
                $this->session->deleteKey('me');
                $this->session->deleteKey('auth');

                $me = $this->validateMe($request->getPostParameter('me'));

                // if discovery is enabled, we try find the authorization_endpoint
                if ($this->discoveryEnabled) {
                    $pageFetcher = new PageFetcher($this->client);
                    $pageResponse = $pageFetcher->fetch($me);
                    //$expectedMe = $pageResponse->getEffectiveUrl();
                    $authUri = $this->extractAuthorizeEndpoint($pageResponse->getBody());
                    if (null !== $authUri) {
                        try {
                            $authUriObj = new Uri($authUri);
                            if ('https' !== $authUriObj->getScheme()) {
                                throw new RuntimeException('authorization_endpoint must be a valid https URL');
                            }
                            $this->authUri = $authUriObj->getUri();
                        } catch (InvalidArgumentException $e) {
                            throw new RuntimeException('authorization_endpoint must be a valid URL');
                        }
                    }
                }

                $clientId = $request->getAbsRoot();
                $redirectUri = $request->getAbsRoot() . 'indieauth/callback';

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

                $authSession = array(
                    'auth_uri' => $this->authUri,
                    'me' => $me,
                    'state' => $stateValue,
                    'redirect_to' => $this->redirectTo
                );
                $this->session->setValue('auth', $authSession);

                $fullAuthUri = sprintf(
                    '%s?client_id=%s&me=%s&redirect_uri=%s&state=%s',
                    $this->authUri,
                    $clientId,
                    $me,
                    $redirectUri,
                    $stateValue
                );

                return new RedirectResponse($fullAuthUri, 302);
            },
            array(
                'skipPlugins' => array(
                    __CLASS__
                )
            )
        );

        $service->get(
            '/indieauth/callback',
            function (Request $request) {
                $authSession = $this->session->getValue('auth');

                $queryState = $this->validateState($request->getQueryParameter('state'));
                $queryCode = $this->validateCode($request->getQueryParameter('code'));

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
                            'client_id' => $request->getAbsRoot(),
                            // https://github.com/aaronpk/IndieAuth.com/issues/81
                            // "state parameter required on verify POST"
                            'state' => $queryState,
                            'code' => $queryCode,
                            'redirect_uri' => $request->getAbsRoot() . 'indieauth/callback'
                        )
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

                $this->session->setValue('me', $responseData['me']);
                $this->session->deleteKey('auth');

                return new RedirectResponse($authSession['redirect_to'], 302);
            },
            array(
                'skipPlugins' => array(
                    __CLASS__
                )
            )
        );
    }

    public function execute(Request $request)
    {
        $userId = $this->session->getValue('me');
        if (null === $userId) {
            throw new UnauthorizedException('not authenticated', 'no authenticated session', 'IndieAuth');
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
        if (0 !== stripos($me, 'http')) {
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
            return $uriObj->getUri();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('"me" is an invalid uri');
        }
    }

    private function extractAuthorizeEndpoint($htmlString)
    {
        $dom = new DomDocument();
        // disable error handling by DomDocument so we handle them ourselves
        libxml_use_internal_errors(true);
        $dom->loadHTML($htmlString);
        // throw away all errors, we do not care about them anyway
        libxml_clear_errors();

        $tags = array('link', 'a');
        $relLinks = array();
        foreach ($tags as $tag) {
            $elements = $dom->getElementsByTagName($tag);
            foreach ($elements as $element) {
                $rel = $element->getAttribute('rel');
                if ('authorization_endpoint' === $rel) {
                    return $element->getAttribute('href');
                }
            }
        }

        return null;
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

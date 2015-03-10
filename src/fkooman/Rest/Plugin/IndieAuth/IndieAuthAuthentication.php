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
use fkooman\Http\Uri;
use InvalidArgumentException;
use DomDocument;

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
            $authUri = 'https://indieauth.com/auth';
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
                $me = $this->validateMe($request->getPostParameter('me'));

                if ($this->discoveryEnabled) {
                    // try to find authorization_endpoint
                    $pageFetcher = new PageFetcher($this->client);
                    $pageResponse = $pageFetcher->fetch($me);
                    $authUri = $this->extractAuthorizeEndpoint($pageResponse->getBody());
                    if (null !== $authUri) {
                        // FIXME: check if it is a valid HTTPS URI
                        $this->authUri = $authUri;
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
                $this->session->deleteKey('me');
                $this->session->setValue('auth_uri', $this->authUri);
                $this->session->setValue('state', $stateValue);
                $this->session->setValue('client_id', $clientId);
                $this->session->setValue('redirect_uri', $redirectUri);
                $this->session->setValue('redirect_to', $this->redirectTo);

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
                    'fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'
                )
            )
        );

        $service->get(
            '/indieauth/callback',
            function (Request $request) {
                $sessionState = $this->session->getValue('state');
                $sessionRedirectUri = $this->session->getValue('redirect_uri');
                $sessionClientId = $this->session->getValue('client_id');
                $authUri = $this->session->getValue('auth_uri');
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
                    $authUri,
                    array(
                        'headers' => array('Accept' => 'application/json'),
                        'body' => array(
                            // FIXME: https://github.com/aaronpk/IndieAuth.com/issues/81
                            'state' => $sessionState,
                            'client_id' => $sessionClientId,
                            'code' => $queryCode,
                            'redirect_uri' => $sessionRedirectUri
                        )
                    )
                );

                // FIXME: we need to verify that what we get back is actual JSON,
                // IndieAuth.com does not yet honor the Accept header, this can
                // all go away when it does...
                $verifyResponse = $this->client->send($verifyRequest);
                $contentType = $verifyResponse->getHeader('Content-Type');
                if (0 === strpos($contentType, 'application/json')) {
                    $verifyData = $verifyResponse->json();
                } elseif (0 === strpos($contentType, 'application/x-www-form-urlencoded')) {
                    $verifyData = array();
                    $responseBody = (string) $verifyResponse->getBody();

                    parse_str((string) $verifyResponse->getBody(), $verifyData);
                } else {
                    throw new RuntimeException('invalid content type from verify endpoint');
                }
                
                if (!array_key_exists('me', $verifyData)) {
                    throw new RuntimeException('me field not found in verify response');
                }

                $this->session->setValue('me', $verifyData['me']);

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'skipPlugins' => array(
                    'fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication'
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
                    ;
                }
            }
        }

        return null;
    }
}

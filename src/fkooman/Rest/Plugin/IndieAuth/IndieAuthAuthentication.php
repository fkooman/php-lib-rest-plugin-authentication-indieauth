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
use GuzzleHttp\Client;
use GuzzleHttp\Message\Response;
use fkooman\Http\Uri;
use InvalidArgumentException;
use DomDocument;
use RuntimeException;

class IndieAuthAuthentication implements ServicePluginInterface
{
    /** @var string */
    private $authUri;

    /** @var string */
    private $tokenUri;

    /** @var boolean */
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
                // HTTP_REFERER needs to start with absRoot, CSRF protection
                if (0 !== strpos($request->getHeader('HTTP_REFERER'), $request->getAbsRoot())) {
                    throw new BadRequestException('request MUST come from the application');
                }

                $this->session->deleteKey('me');
                $this->session->deleteKey('access_token');
                $this->session->deleteKey('scope');
                $this->session->deleteKey('auth');

                $me = $this->validateMe($request->getPostParameter('me'));
                $scope = $this->validateScope($request->getPostParameter('scope'));

                // if discovery is enabled, we try find the authorization_endpoint
                if ($this->discoveryEnabled) {
                    $pageFetcher = new PageFetcher($this->client);
                    $pageResponse = $pageFetcher->fetch($me);
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
                    $tokenUri = $this->extractTokenEndpoint($pageResponse->getBody());
                    // FIXME: url checking code duplication!
                    if (null !== $tokenUri) {
                        try {
                            $tokenUriObj = new Uri($tokenUri);
                            if ('https' !== $tokenUriObj->getScheme()) {
                                throw new RuntimeException('token_endpoint must be a valid https URL');
                            }
                            $this->tokenUri = $tokenUriObj->getUri();
                        } catch (InvalidArgumentException $e) {
                            throw new RuntimeException('token_endpoint must be a valid URL');
                        }
                    }
                }

                $clientId = $request->getAbsRoot();
                $redirectUri = $request->getAbsRoot() . 'indieauth/callback';
                $stateValue = $this->io->getRandomHex();
                $redirectTo = $this->validateRedirectTo($request, $request->getPostParameter('redirect_to'));

                $authSession = array(
                    'auth_uri' => $this->authUri,
                    'token_uri' => $this->tokenUri,
                    'me' => $me,
                    'state' => $stateValue,
                    'redirect_to' => $redirectTo
                );
                if (null !== $scope) {
                    $authSession['scope'] = $scope;
                }

                $this->session->setValue('auth', $authSession);

                $authUriParams = array(
                    'client_id' => $clientId,
                    'me' => $me,
                    'redirect_uri' => $redirectUri,
                    'state' => $stateValue
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

                // if we requested a scope, we also want an access token
                if (array_key_exists('scope', $authSession) && null !== $authSession['scope']) {
                    $verifyRequest = $this->client->createRequest(
                        'POST',
                        $authSession['token_uri'],
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
                    $this->session->setValue('access_token', $responseData['access_token']);
                    $this->session->setValue('scope', $responseData['scope']);
                }

                $this->session->deleteKey('auth');

                return new RedirectResponse($authSession['redirect_to'], 302);
            },
            array(
                'skipPlugins' => array(
                    __CLASS__
                )
            )
        );

        $service->get(
            '/indieauth/logout',
            function (Request $request) {
                // HTTP_REFERER needs to start with absRoot, CSRF protection
                if (0 !== strpos($request->getHeader('HTTP_REFERER'), $request->getAbsRoot())) {
                    throw new BadRequestException('request MUST come from the application');
                }

                $this->session->destroy();
                $redirectTo = $this->validateRedirectTo($request, $request->getQueryParameter('redirect_to'));

                return new RedirectResponse($redirectTo, 302);
            },
            array(
                'skipPlugins' => array(
                    __CLASS__
                )
            )
        );
    }

    public function execute(Request $request, array $routeConfig)
    {
        $userId = $this->session->getValue('me');
        $accessToken = $this->session->getValue('access_token');
        $scope = $this->session->getValue('scope');

        if (null === $userId) {
            // check if authentication is required...
            if (array_key_exists('requireAuth', $routeConfig)) {
                if (!$routeConfig['requireAuth']) {
                    return false;
                }
            }

            if (null !== $this->unauthorizedRedirectUri) {
                $redirectTo = $this->validateRedirectTo($request, $this->unauthorizedRedirectUri);

                return new RedirectResponse($redirectTo, 302);
            }

            throw new UnauthorizedException('not authenticated', 'no authenticated session', 'IndieAuth');
        }

        return new IndieInfo($userId, $accessToken, $scope);
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

    private function validateRedirectTo(Request $request, $redirectTo)
    {
        // no redirectTo specified
        if (null === $redirectTo) {
            $redirectTo = $request->getAbsRoot();
        }

        // redirectTo specified, using path relative to absRoot
        if (0 === strpos($redirectTo, '/')) {
            $redirectTo = $request->getAbsRoot() . substr($redirectTo, 1);
        }

        // validate and normalize the URL
        try {
            $redirectToObj = new Uri($redirectTo);
            $redirectTo = $redirectToObj->getUri();
        } catch (InvalidArgumentException $e) {
            throw new BadRequestException('invalid redirect_to URL');
        }

        // URL needs to start with absRoot
        if (0 !== strpos($redirectTo, $request->getAbsRoot())) {
            throw new BadRequestException('redirect_to needs to point to a URL relative to the application root');
        }
        
        return $redirectTo;
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

    private function validateScope($scope)
    {
        return $scope;

#        // allow scope to be missing
#        if (null === $scope) {
#            return null;
#        }

#        // but if it is there, it needs to be a valid scope and also
#        // 'normalized'
#        try {
#            $scopeObj = new Scope($scope);
#            return $scopeObj->toString();
#        } catch(InvalidArgumentException $e) {
#            throw new BadRequestException('"scope" is invalid', $e->getMessage());
#        }
    }

    private function extractAuthorizeEndpoint($htmlString)
    {
        $relLinks = $this->extractRelLinks($htmlString);
        foreach ($relLinks as $key => $value) {
            if ('authorization_endpoint' === $key) {
                return $value;
            }
        }
        return null;
    }

    private function extractTokenEndpoint($htmlString)
    {
        $relLinks = $this->extractRelLinks($htmlString);
        foreach ($relLinks as $key => $value) {
            if ('token_endpoint' === $key) {
                return $value;
            }
        }
        return null;
    }
    
    // FIXME: this method is now called twice, invoking the dom parser twice,
    // inefficient!
    private function extractRelLinks($htmlString)
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
                if (null !== $rel) {
                    $relLinks[$rel] = $element->getAttribute('href');
                }
            }
        }

        return $relLinks;
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

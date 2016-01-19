<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
namespace fkooman\Rest\Plugin\Authentication\IndieAuth;

require_once __DIR__.'/Test/TestTemplateManager.php';
require_once __DIR__.'/Test/TestSession.php';

use PHPUnit_Framework_TestCase;
use fkooman\Rest\Plugin\Authentication\IndieAuth\Test\TestTemplateManager;
use fkooman\Http\SessionInterface;
use fkooman\Rest\Plugin\Authentication\IndieAuth\Test\TestSession;
use fkooman\Http\Request;
use fkooman\Rest\Service;
use fkooman\Rest\Plugin\Authentication\AuthenticationPlugin;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;

class IndieAuthAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testAuth()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $testSession = new TestSession();
        $testSession->set('_auth_indieauth_me', 'https://foo.example.org/');
        $indieAuth = $this->getIndieAuth($testSession);
        $this->assertEquals('https://foo.example.org/', $indieAuth->isAuthenticated($request)->getUserId());
    }

#    public function testAuthNonMatchingLoginHint()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => 'login_hint=bar',
#                'REQUEST_URI' => '/?login_hint=bar',
#                'SCRIPT_NAME' => '/index.php',
#                'REQUEST_METHOD' => 'GET',
#            )
#        );
#        $testSession = new TestSession();
#        $testSession->set('_auth_form_user_name', 'foo');
#        $indieAuth = $this->getIndieAuth($testSession);
#        $this->assertFalse($indieAuth->isAuthenticated($request));
#    }

    public function testAuthNotAuthenticated()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'login_hint=https://foo.example.org/',
                'REQUEST_URI' => '/?login_hint=https://foo.example.org/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $testSession = new TestSession();
        $indieAuth = $this->getIndieAuth($testSession);
        $this->assertFalse($indieAuth->isAuthenticated($request));
        $response = $indieAuth->requestAuthentication($request);
        $this->assertSame(
            array(
                'HTTP/1.1 200 OK',
                'Content-Type: text/html;charset=UTF-8',
                'X-Frame-Options: DENY',
                "Content-Security-Policy: default-src 'self'",
                'Content-Length: 102',
                '',
                '{"indieAuthAuth":{"login_hint":"https:\/\/foo.example.org\/","root_url":"http:\/\/www.example.org\/"}}',
            ),
            $response->toArray()
        );
        $this->assertNull($testSession->get('_auth_indieauth_me'));
    }

#    public function testAuthNotAuthenticatedAfterAttempt()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => 'login_hint=foo',
#                'REQUEST_URI' => '/?login_hint=foo',
#                'SCRIPT_NAME' => '/index.php',
#                'REQUEST_METHOD' => 'GET',
#            )
#        );
#        $testSession = new TestSession();
#        $testSession->set('_auth_form_invalid_credentials', true);
#        $testSession->set('_auth_form_invalid_user_name', 'fooz');
#        $indieAuth = $this->getIndieAuth($testSession);
#        $this->assertFalse($indieAuth->isAuthenticated($request));
#        $response = $indieAuth->requestAuthentication($request);
#        $this->assertSame(
#            array(
#                'HTTP/1.1 200 OK',
#                'Content-Type: text/html;charset=UTF-8',
#                'X-Frame-Options: DENY',
#                "Content-Security-Policy: default-src 'self'",
#                'Content-Length: 109',
#                '',
#                '{"formAuth":{"login_hint":"foo","_auth_form_invalid_credentials":true,"_auth_form_invalid_user_name":"fooz"}}',
#            ),
#            $response->toArray()
#        );
#        $this->assertNull($testSession->get('_auth_form_user_name'));
#    }

    public function testAuthRequest()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'HTTP_ACCEPT' => 'text/html',
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_auth/indieauth/auth',
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/indieauth/auth',
                'REQUEST_METHOD' => 'POST',
            ),
            array(
                'me' => 'https://foo.example.org/',
                //'redirect_to' => 'http://foo.example.org/',
            )
        );
        $service = new Service();
        $testSession = new TestSession();
        $indieAuth = $this->getIndieAuth($testSession);
        $indieAuth->setAuthUri('https://auth.example.org/auth');
        $ap = new AuthenticationPlugin();
        $ap->register($indieAuth, 'indieauth');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: https://auth.example.org/auth?client_id=http%3A%2F%2Fwww.example.org%2F&response_type=code&me=https%3A%2F%2Ffoo.example.org%2F&redirect_uri=http%3A%2F%2Fwww.example.org%2F_auth%2Findieauth%2Fcallback&state=abcd1234',
                '',
                '',
            ),
            $response->toArray()
        );
        $this->assertSame(
            array(
                'client_id' => 'http://www.example.org/',
                'auth_uri' => 'https://auth.example.org/auth',
                'me' => 'https://foo.example.org/',
                'state' => 'abcd1234',
                'redirect_uri' => 'http://www.example.org/_auth/indieauth/callback',
                'redirect_to' => 'http://www.example.org/',
            ),
            $testSession->get('_auth_indieauth_session')
        );
        $this->assertNull($testSession->get('_auth_indieauth_me'));
    }

    public function testCallback()
    {
        $q = array(
            'state' => 'abcd1234',
            'code' => '1234',
        );

        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'HTTP_ACCEPT' => 'text/html',
                'QUERY_STRING' => http_build_query($q),
                'REQUEST_URI' => sprintf('/_auth/indieauth/callback?%s', http_build_query($q)),
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/indieauth/callback',
                'REQUEST_METHOD' => 'GET',
            )
        );

        $service = new Service();
        $testSession = new TestSession();
        $testSession->set(
            '_auth_indieauth_session',
            array(
                'client_id' => 'http://www.example.org/',
                'auth_uri' => 'https://auth.example.org/auth',
                'me' => 'https://foo.example.org/',
                'state' => 'abcd1234',
                'redirect_uri' => 'http://www.example.org/_auth/indieauth/callback',
                'redirect_to' => 'http://www.example.org/',
            )
        );

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array(
                        'Content-Type' => 'application/json',
                    ),
                    Stream::factory(
                        json_encode(
                            array('me' => 'https://foo.example.org/')
                        )
                    )
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $indieAuth = $this->getIndieAuth($testSession, $client);
        $indieAuth->setAuthUri('https://auth.example.org/');
        $ap = new AuthenticationPlugin();
        $ap->register($indieAuth, 'indieauth');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);

        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );

        $this->assertEquals('https://foo.example.org/', $testSession->get('_auth_indieauth_me'));
        $this->assertNull($testSession->get('_auth_indieauth_session'));
    }

    public function testLogout()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'HTTP_ACCEPT' => 'text/html',
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_auth/indieauth/logout',
                'SCRIPT_NAME' => '/index.php',
                'HTTP_REFERER' => 'http://www.example.org/',
                'PATH_INFO' => '/_auth/indieauth/logout',
                'REQUEST_METHOD' => 'POST',
            ),
            array(
                'redirect_to' => 'http://elsewhere.example.org/',
            )
        );
        $service = new Service();
        $testSession = new TestSession();
        $indieAuth = $this->getIndieAuth($testSession);
        $indieAuth->setAuthUri('https://auth.example.org/auth');
        $ap = new AuthenticationPlugin();
        $ap->register($indieAuth, 'indieauth');
        $service->getPluginRegistry()->registerDefaultPlugin($ap);
        $response = $service->run($request);
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://elsewhere.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
    }

#    public function testVerifyWrongUser()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => '',
#                'HTTP_ACCEPT' => 'text/html',
#                'REQUEST_URI' => '/_auth/form/verify',
#                'SCRIPT_NAME' => '/index.php',
#                'HTTP_REFERER' => 'http://www.example.org/',
#                'PATH_INFO' => '/_auth/form/verify',
#                'REQUEST_METHOD' => 'POST',
#            ),
#            array(
#                'userName' => 'fooz',
#                'userPass' => 'bar',
#            )
#        );
#        $service = new Service();
#        $testSession = new TestSession();
#        $indieAuth = $this->getIndieAuth($testSession);
#        $ap = new AuthenticationPlugin();
#        $ap->register($indieAuth, 'form');
#        $service->getPluginRegistry()->registerDefaultPlugin($ap);
#        $response = $service->run($request);
#        $this->assertSame(
#            array(
#                'HTTP/1.1 302 Found',
#                'Content-Type: text/html;charset=UTF-8',
#                'Location: http://www.example.org/',
#                '',
#                '',
#            ),
#            $response->toArray()
#        );
#        $this->assertTrue($testSession->get('_auth_form_invalid_credentials'));
#        $this->assertSame('fooz', $testSession->get('_auth_form_invalid_user_name'));
#        $this->assertNull($testSession->get('_auth_form_user_name'));
#    }

#    public function testVerifyWrongPass()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => '',
#                'HTTP_ACCEPT' => 'text/html',
#                'REQUEST_URI' => '/_auth/form/verify',
#                'SCRIPT_NAME' => '/index.php',
#                'HTTP_REFERER' => 'http://www.example.org/',
#                'PATH_INFO' => '/_auth/form/verify',
#                'REQUEST_METHOD' => 'POST',
#            ),
#            array(
#                'userName' => 'foo',
#                'userPass' => 'baz',
#            )
#        );
#        $service = new Service();
#        $testSession = new TestSession();
#        $indieAuth = $this->getIndieAuth($testSession);
#        $ap = new AuthenticationPlugin();
#        $ap->register($indieAuth, 'form');
#        $service->getPluginRegistry()->registerDefaultPlugin($ap);
#        $response = $service->run($request);
#        $this->assertSame(
#            array(
#                'HTTP/1.1 302 Found',
#                'Content-Type: text/html;charset=UTF-8',
#                'Location: http://www.example.org/',
#                '',
#                '',
#            ),
#            $response->toArray()
#        );
#        $this->assertTrue($testSession->get('_auth_form_invalid_credentials'));
#    }

#    public function testLogout()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => '',
#                'HTTP_ACCEPT' => 'text/html',
#                'REQUEST_URI' => '/_auth/form/logout',
#                'SCRIPT_NAME' => '/index.php',
#                'PATH_INFO' => '/_auth/form/logout',
#                'REQUEST_METHOD' => 'POST',
#                'HTTP_REFERER' => 'http://www.example.org/',
#            )
#        );
#        $service = new Service();
#        $testSession = new TestSession();
#        $testSession->set('_auth_form_user_name', 'foo');
#        $indieAuth = $this->getIndieAuth($testSession);
#        $ap = new AuthenticationPlugin();
#        $ap->register($indieAuth, 'form');
#        $service->getPluginRegistry()->registerDefaultPlugin($ap);
#        $response = $service->run($request);
#        $this->assertSame(
#            array(
#                'HTTP/1.1 302 Found',
#                'Content-Type: text/html;charset=UTF-8',
#                'Location: http://www.example.org/',
#                '',
#                '',
#            ),
#            $response->toArray()
#        );
#        $this->assertNull($testSession->get('_auth_form_user_name'));
#    }

#    public function testLogoutRedirectTo()
#    {
#        $request = new Request(
#            array(
#                'SERVER_NAME' => 'www.example.org',
#                'SERVER_PORT' => 80,
#                'QUERY_STRING' => '',
#                'HTTP_ACCEPT' => 'text/html',
#                'REQUEST_URI' => '/_auth/form/logout',
#                'SCRIPT_NAME' => '/index.php',
#                'PATH_INFO' => '/_auth/form/logout',
#                'REQUEST_METHOD' => 'POST',
#                'HTTP_REFERER' => 'http://www.example.org/',
#            ),
#            array(
#                'redirect_to' => 'http://my-domain.org/loggedOut',
#            )
#        );
#        $service = new Service();
#        $testSession = new TestSession();
#        $testSession->set('_auth_form_user_name', 'foo');
#        $indieAuth = $this->getIndieAuth($testSession);
#        $ap = new AuthenticationPlugin();
#        $ap->register($indieAuth, 'form');
#        $service->getPluginRegistry()->registerDefaultPlugin($ap);
#        $response = $service->run($request);
#        $this->assertSame(
#            array(
#                'HTTP/1.1 302 Found',
#                'Content-Type: text/html;charset=UTF-8',
#                'Location: http://my-domain.org/loggedOut',
#                '',
#                '',
#            ),
#            $response->toArray()
#        );
#        $this->assertNull($testSession->get('_auth_form_user_name'));
#    }

    private function getIndieAuth(SessionInterface $session, Client $client = null)
    {
        $io = $this->getMockBuilder('fkooman\IO\IO')->getMock();
        $io->method('getRandom')->will($this->returnValue('abcd1234'));

        $indieAuth = new IndieAuthAuthentication(
            new TestTemplateManager(),
            $client,
            $session,
            $io
        );

        return $indieAuth;
    }
}

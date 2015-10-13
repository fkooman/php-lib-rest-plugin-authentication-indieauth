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

use fkooman\Rest\Service;
use fkooman\Http\Request;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use PHPUnit_Framework_TestCase;

class IndieAuthAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testIndieAuthAuthenticated()
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
        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $map = array(
            array(
                'auth',
                array(
                    'client_id' => 'http://www.example.org/',
                    'state' => '12345abcdef',
                    'redirect_to' => 'http://www.example.org/',
                    'auth_uri' => 'https://indiefoo.net/auth',
                ),
            ),
            array('me', 'https://mydomain.org/'),
        );
        $sessionStub->method('get')
             ->will($this->returnValueMap($map));

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init(new Service());
        $userInfo = $indieAuthAuth->execute($request, array());
        $this->assertEquals('https://mydomain.org/', $userInfo->getUserId());
    }

    /**
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage no_credentials
     */
    public function testIndieAuthNotAuthenticated()
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
        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);

        $indieAuthAuth->init(new Service());
        $indieAuthAuth->execute($request, array());
    }

    public function testIndieAuthNotAuthenticatedUnauthorizedRedirectUri()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'me=https://foo.example.org/',
                'REQUEST_URI' => '/foo?me=https://foo.example.org/',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_METHOD' => 'GET',
            )
        );
        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->setUnauthorizedRedirectUri('/foo/bar?action=def');

        $indieAuthAuth->init(new Service());
        $this->assertTrue($indieAuthAuth->isAttempt($request));
        $response = $indieAuthAuth->execute($request, array());
        $this->assertSame(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/foo/bar?action=def&me=https://foo.example.org/&redirect_to=http%3A%2F%2Fwww.example.org%2Ffoo%3Fme%3Dhttps%3A%2F%2Ffoo.example.org%2F',
                '',
                '',
            ),
            $response->toArray()
        );
    }

    public function testIndieAuthAuthRequest()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 443,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/_indieauth/auth',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_indieauth/auth',
                'REQUEST_METHOD' => 'POST',
                'HTTP_REFERER' => 'https://www.example.org/',
                'HTTPS' => 'on',
            ),
            array(
                'me' => 'mydomain.org',
            )
        );

        $ioStub = $this->getMockBuilder('fkooman\IO\IO')
                     ->disableOriginalConstructor()
                     ->getMock();
        $ioStub->method('getRandom')->willReturn(
            '12345abcdef'
        );

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'text/html'),
                    Stream::factory(
                        file_get_contents(__DIR__.'/data/fkooman.html')
                    )
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $service = new Service();
        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->setIo($ioStub);
        $indieAuthAuth->setClient($client);
        $indieAuthAuth->init($service);

        $response = $service->run($request);

        $this->assertEquals(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: https://indiecert.net/auth?client_id=https%3A%2F%2Fwww.example.org%2F&response_type=code&me=https%3A%2F%2Fmydomain.org%2F&redirect_uri=https%3A%2F%2Fwww.example.org%2F_indieauth%2Fcallback&state=12345abcdef',
                '',
                '',
            ),
            $response->toArray()
        );
    }

    public function testIndieAuthCallbackNoSessionState()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321',
                'REQUEST_URI' => '/_indieauth/callback?code=54321',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_indieauth/callback',
                'REQUEST_METHOD' => 'GET',
            )
        );

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $service = new Service();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init($service);

        $this->assertSame(
            array(
                'HTTP/1.1 400 Bad Request',
                'Content-Type: application/json',
                'Content-Length: 32',
                '',
                '{"error":"no session available"}',
            ),
            $service->run($request)->toArray()
        );
    }

    public function testIndieAuthCallbackNonMatchingState()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/_indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_indieauth/callback',
                'REQUEST_METHOD' => 'GET',
            )
        );

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('get')->willReturn(array('state' => '54321abcdef'));

        $service = new Service();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init($service);

        $this->assertSame(
            array(
                'HTTP/1.1 400 Bad Request',
                'Content-Type: application/json',
                'Content-Length: 30',
                '',
                '{"error":"non matching state"}',
            ),
            $service->run($request)->toArray()
        );
    }

    public function testIndieAuthCallbackJson()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/_indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_indieauth/callback',
                'REQUEST_METHOD' => 'GET',
                'HTTP_ACCEPT' => 'application/json',
            )
        );

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            array(
                'auth',
                array(
                    'client_id' => 'http://www.example.org/',
                    'state' => '12345abcdef',
                    'redirect_uri' => 'http://www.example.org/_indieauth/callback',
                    'redirect_to' => 'http://www.example.org/',
                    'auth_uri' => 'https://indiefoo.net/auth',
                    'me' => 'https://mydomain.org/',
                ),
            ),
            array('me', 'https://mydomain.org/'),
        );
        $sessionStub->method('get')
             ->will($this->returnValueMap($map));

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'application/json'),
                    Stream::factory(
                        json_encode(
                            array(
                                'me' => 'https://mydomain.org/',
                            )
                        )
                    )
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $service = new Service();
        $indieAuthAuth = new IndieAuthAuthentication();

        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->setClient($client);
        $indieAuthAuth->init($service);

        $response = $service->run($request);
        $this->assertEquals(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
    }

    public function testIndieAuthCallbackForm()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/_indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/_indieauth/callback',
                'REQUEST_METHOD' => 'GET',
                'HTTP_ACCEPT' => 'application/x-www-form-urlencoded',
            )
        );

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            array(
                'auth',
                array(
                    'state' => '12345abcdef',
                    'redirect_to' => 'http://www.example.org/',
                    'auth_uri' => 'https://indiefoo.net/auth',
                    'me' => 'https://mydomain.org/',
                    'client_id' => 'http://www.example.org/',
                    'redirect_uri' => 'http://www.example.org/_indieauth/callback',
                ),
            ),
            array('me', 'https://mydomain.org/'),
        );
        $sessionStub->method('get')
             ->will($this->returnValueMap($map));

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'application/x-www-form-urlencoded'),
                    Stream::factory(
                        'me=https%3A%2F%2Fmydomain.org%2F'
                    )
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $service = new Service();
        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->setClient($client);
        $indieAuthAuth->init($service);

        $response = $service->run($request);
        $this->assertEquals(
            array(
                'HTTP/1.1 302 Found',
                'Content-Type: text/html;charset=UTF-8',
                'Location: http://www.example.org/',
                '',
                '',
            ),
            $response->toArray()
        );
    }
}

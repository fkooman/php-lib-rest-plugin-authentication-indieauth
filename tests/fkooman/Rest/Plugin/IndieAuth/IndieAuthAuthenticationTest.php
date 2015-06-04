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
namespace fkooman\Rest;

use fkooman\Http\Request;
use fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication;
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
        $sessionStub->method('get')->willReturn(
            'https://mydomain.org/'
        );

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init(new Service());
        $userInfo = $indieAuthAuth->execute($request, array());
        $this->assertEquals('https://mydomain.org/', $userInfo->getUserId());
    }

    /**
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage not authenticated
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

    public function testIndieAuthAuthRequest()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 443,
                'QUERY_STRING' => '',
                'REQUEST_URI' => '/indieauth/auth',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/indieauth/auth',
                'REQUEST_METHOD' => 'POST',
                'HTTP_REFERER' => 'https://www.example.org/',
                'HTTPS' => 'on',
            ),
            array(
                'me' => 'mydomain.org',
            )
        );

#        $request = new Request('https://www.example.org/indieauth/auth', 'POST');
#        $request->setRoot('/');
#        $request->setPathInfo('/indieauth/auth');
#        $request->setHeaders(
#            array(
#                'HTTP_REFERER' => 'https://www.example.org/'
#            )
#        );

#        $request->setPostParameters(
#            array(
#                'me' => 'mydomain.org'
#            )
#        );

        $ioStub = $this->getMockBuilder('fkooman\Rest\Plugin\IndieAuth\IO')
                     ->disableOriginalConstructor()
                     ->getMock();
        $ioStub->method('getRandomHex')->willReturn(
            '12345abcdef'
        );

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'text/html'),
                    Stream::factory(
                        file_get_contents(dirname(dirname(dirname(dirname(__DIR__)))).'/data/fkooman.html')
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
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals(
            'https://indiecert.net/auth?client_id=https%3A%2F%2Fwww.example.org%2F&me=https%3A%2F%2Fmydomain.org%2F&redirect_uri=https%3A%2F%2Fwww.example.org%2Findieauth%2Fcallback&state=12345abcdef',
            $response->getHeader('Location')
        );
    }

    /**
     * @expectedException fkooman\Http\Exception\BadRequestException
     * @expectedExceptionMessage no session available
     */
    public function testIndieAuthCallbackNoSessionState()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321',
                'REQUEST_URI' => '/indieauth/callback?code=54321',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/indieauth/callback',
                'REQUEST_METHOD' => 'GET',
            )
        );

#        $request = new Request('http://www.example.org/indieauth/callback?code=54321', 'GET');
#        $request->setRoot('/');
#        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $service = new Service();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init($service);

        $service->run($request);
    }

    /**
     * @expectedException fkooman\Http\Exception\BadRequestException
     * @expectedExceptionMessage non matching state
     */
    public function testIndieAuthCallbackNonMatchingState()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/indieauth/callback',
                'REQUEST_METHOD' => 'GET',
            )
        );

#        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
#        $request->setRoot('/');
#        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('get')->willReturn(array('state' => '54321abcdef'));

        $service = new Service();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init($service);

        $service->run($request);
    }

    public function testIndieAuthCallbackJson()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/indieauth/callback',
                'REQUEST_METHOD' => 'GET',
                'HTTP_ACCEPT' => 'application/json',
            )
        );

#        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
#        $request->setRoot('/');
#        $request->setHeaders(array('Accept' => 'application/json'));
#        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            'state' => '12345abcdef',
            'redirect_to' => 'http://www.example.org/',
            'auth_uri' => 'https://indiefoo.net/auth',
            'me' => 'https://mydomain.org/',
        );
        $sessionStub->method('get')->willReturn($map);

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
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('http://www.example.org/', $response->getHeader('Location'));
    }

    public function testIndieAuthCallbackForm()
    {
        $request = new Request(
            array(
                'SERVER_NAME' => 'www.example.org',
                'SERVER_PORT' => 80,
                'QUERY_STRING' => 'code=54321&state=12345abcdef',
                'REQUEST_URI' => '/indieauth/callback?code=54321&state=12345abcdef',
                'SCRIPT_NAME' => '/index.php',
                'PATH_INFO' => '/indieauth/callback',
                'REQUEST_METHOD' => 'GET',
                'HTTP_ACCEPT' => 'application/x-www-form-urlencoded',
            )
        );

#        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
#        $request->setRoot('/');
#        $request->setHeaders(array('Accept' => 'application/x-www-form-urlencoded'));
#        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            'state' => '12345abcdef',
            'redirect_to' => 'http://www.example.org/',
            'auth_uri' => 'https://indiefoo.net/auth',
            'me' => 'https://mydomain.org/',
        );
        $sessionStub->method('get')->willReturn($map);

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
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('http://www.example.org/', $response->getHeader('Location'));
    }
}

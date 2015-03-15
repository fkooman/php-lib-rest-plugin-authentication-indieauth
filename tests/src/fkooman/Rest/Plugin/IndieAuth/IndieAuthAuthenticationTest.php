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

namespace fkooman\Rest;

use fkooman\Http\Request;
use fkooman\Rest\Plugin\IndieAuth\IndieAuthAuthentication;
use fkooman\Rest\Plugin\IndieAuth\IO;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use PHPUnit_Framework_TestCase;

class IndieAuthAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testIndieAuthAuthenticated()
    {
        $request = new Request('http://www.example.org/foo', 'GET');
        //$service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn(
            'https://mydomain.org/'
        );

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init(new Service());
        $userInfo = $indieAuthAuth->execute($request);
        $this->assertEquals('https://mydomain.org/', $userInfo->getUserId());
    }

    /**
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage not authenticated
     */
    public function testIndieAuthNotAuthenticated()
    {
        $request = new Request('http://www.example.org/foo', 'GET');
        //$service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);

        $indieAuthAuth->init(new Service());
        $indieAuthAuth->execute($request);
    }

    public function testIndieAuthAuthRequest()
    {
        $request = new Request('http://www.example.org/indieauth/auth', 'POST');
        $request->setRoot('/');
        $request->setPathInfo('/indieauth/auth');
        $request->setHeaders(
            array(
                'HTTP_REFERER' => 'http://www.example.org/'
            )
        );
        $request->setPostParameters(
            array(
                'me' => 'mydomain.org'
            )
        );
                      
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
                        file_get_contents(dirname(dirname(dirname(dirname(dirname(__DIR__))))) . '/data/fkooman.html')
                    )
                )
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
            'https://indiecert.net/auth?client_id=http://www.example.org/&me=https://mydomain.org/&redirect_uri=http://www.example.org/indieauth/callback&state=12345abcdef',
            $response->getHeader('Location')
        );
    }

    /**
     * @expectedException fkooman\Http\Exception\BadRequestException
     * @expectedExceptionMessage missing parameter "state"
     */
    public function testIndieAuthCallbackNoSessionState()
    {
        $request = new Request('http://www.example.org/indieauth/callback?code=54321', 'GET');
        $request->setRoot('/');
        $request->setPathInfo('/indieauth/callback');

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
        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
        $request->setRoot('/');
        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn(array('state' => '54321abcdef'));

        $service = new Service();

        $indieAuthAuth = new IndieAuthAuthentication();
        $indieAuthAuth->setSession($sessionStub);
        $indieAuthAuth->init($service);

        $service->run($request);
    }

    public function testIndieAuthCallbackJson()
    {
        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
        $request->setRoot('/');
        $request->setHeaders(array('Accept' => 'application/json'));
        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            'state' => '12345abcdef',
            'redirect_to' => 'http://www.example.org/',
            'auth_uri' => 'https://indiefoo.net/auth',
            'me' => 'https://mydomain.org/'
        );
        $sessionStub->method('getValue')->willReturn($map);

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'application/json'),
                    Stream::factory(
                        json_encode(
                            array(
                                'me' => 'https://mydomain.org/'
                            )
                        )
                    )
                )
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
        $request = new Request('http://www.example.org/indieauth/callback?code=54321&state=12345abcdef', 'GET');
        $request->setRoot('/');
        $request->setHeaders(array('Accept' => 'application/x-www-form-urlencoded'));
        $request->setPathInfo('/indieauth/callback');

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $map = array(
            'state' => '12345abcdef',
            'redirect_to' => 'http://www.example.org/',
            'auth_uri' => 'https://indiefoo.net/auth',
            'me' => 'https://mydomain.org/'
        );
        $sessionStub->method('getValue')->willReturn($map);

        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'application/x-www-form-urlencoded'),
                    Stream::factory(
                        'me=https%3A%2F%2Fmydomain.org%2F'
                    )
                )
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

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
use fkooman\Rest\Plugin\IndieCert\IndieCertAuthentication;
use fkooman\Rest\Plugin\IndieCert\IO;
use fkooman\Rest\Service;
use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use PHPUnit_Framework_TestCase;

class IndieCertAuthenticationTest extends PHPUnit_Framework_TestCase
{
    public function testIndieCertAuthenticated()
    {
        $request = new Request('http://www.example.org/foo', 'GET');
        $service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn(
            'https://mydomain.org/'
        );

        $indieCertAuth = new IndieCertAuthentication($service, null, null, null, $sessionStub);
        $userInfo = $indieCertAuth->execute($request);
        $this->assertEquals('https://mydomain.org/', $userInfo->getUserId());
    }

    /**
     * @expectedException fkooman\Http\Exception\UnauthorizedException
     * @expectedExceptionMessage not authenticated
     */
    public function testIndieCertNotAuthenticated()
    {
        $request = new Request('http://www.example.org/foo', 'GET');
        $service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn(
            null
        );

        $indieCertAuth = new IndieCertAuthentication($service, null, null, null, $sessionStub);
        $indieCertAuth->execute($request);
    }

    public function testIndieCertAuthRequest()
    {
        $request = new Request('http://www.example.org/indiecert/auth', 'POST');
        $request->setAppRoot('/');
        $request->setPathInfo('/indiecert/auth');
        $request->setHeader('HTTP_REFERER', 'http://www.example.org/');
        $request->setPostParameters(
            array(
                'me' => 'mydomain.org'
            )
        );
                      
        $service = new Service();

        $ioStub = $this->getMockBuilder('fkooman\Rest\Plugin\IndieCert\IO')
                     ->disableOriginalConstructor()
                     ->getMock();
        $ioStub->method('getRandomHex')->willReturn(
            '12345abcdef'
        );


        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('setValue')->willReturn(
            null
        );

        $indieCertAuth = new IndieCertAuthentication($service, null, 'https://indiecert.net/auth', null, $sessionStub, null, $ioStub);
        $response = $service->run($request);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals(
            'https://indiecert.net/auth?me=mydomain.org&redirect_uri=http://www.example.org/indiecert/callback&state=12345abcdef',
            $response->getHeader('Location')
        );
    }

    public function testIndieCertCallbackNoSessionState()
    {
        $request = new Request('http://www.example.org/indiecert/callback?code=54321', 'GET');
        $request->setAppRoot('/');
        $request->setPathInfo('/indiecert/callback');

        $service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn(null);

        $indieCertAuth = new IndieCertAuthentication($service, null, null, null, $sessionStub);
        $response = $service->run($request);
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals(array('error' => 'no session state available'), $response->getContent());
    }

    public function testIndieCertCallbackNonMatchingState()
    {
        $request = new Request('http://www.example.org/indiecert/callback?code=54321&state=12345abcdef', 'GET');
        $request->setAppRoot('/');
        $request->setPathInfo('/indiecert/callback');

        $service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->willReturn('54321abcdef');

        $indieCertAuth = new IndieCertAuthentication($service, null, null, null, $sessionStub);
        $response = $service->run($request);
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals(array('error' => 'non matching state'), $response->getContent());
    }

    public function testIndieCertCallback()
    {
        $request = new Request('http://www.example.org/indiecert/callback?code=54321&state=12345abcdef', 'GET');
        $request->setAppRoot('/');
        $request->setPathInfo('/indiecert/callback');

        $service = new Service();

        $sessionStub = $this->getMockBuilder('fkooman\Http\Session')
                     ->disableOriginalConstructor()
                     ->getMock();
        $sessionStub->method('getValue')->will($this->onConsecutiveCalls('12345abcdef', 'http://www.example.org/indiecert/callback', 'http://www.example.org/'));
        $sessionStub->method('setValue')->willReturn(null);

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

        $indieCertAuth = new IndieCertAuthentication($service, null, null, null, $sessionStub, $client);
        $response = $service->run($request);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('http://www.example.org/', $response->getHeader('Location'));
    }
}

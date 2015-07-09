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

namespace fkooman\Rest\Plugin\IndieAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Stream\Stream;
use PHPUnit_Framework_TestCase;

class DiscoveryTest extends PHPUnit_Framework_TestCase
{
    public function testDiscovery()
    {
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

        $discovery = new Discovery($client);
        $discoveryResponse = $discovery->discover('https://www.tuxed.net/fkooman/');
        $this->assertEquals('https://indiecert.net/auth', $discoveryResponse->getAuthorizationEndpoint());
        $this->assertEquals('https://indiecert.net/token', $discoveryResponse->getTokenEndpoint());
    }

    public function testDiscoveryNoEndpoints()
    {
        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    200,
                    array('Content-Type' => 'text/html'),
                    Stream::factory('Hello World')
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $discovery = new Discovery($client);
        $discoveryResponse = $discovery->discover('https://www.tuxed.net/fkooman/');
        $this->assertNull($discoveryResponse->getAuthorizationEndpoint());
        $this->assertNull($discoveryResponse->getTokenEndpoint());
    }

    /**
     * @expectedException GuzzleHttp\Exception\ClientException
     */
    public function testDiscoveryNotFound()
    {
        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    404,
                    array('Content-Type' => 'text/html'),
                    Stream::factory('Not Found')
                ),
            )
        );
        $client->getEmitter()->attach($mock);

        $discovery = new Discovery($client);
        $discoveryResponse = $discovery->discover('https://www.tuxed.net/fkooman/');
        $this->assertNull($discoveryResponse->getAuthorizationEndpoint());
        $this->assertNull($discoveryResponse->getTokenEndpoint());
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage URL must be a valid https URL
     */
    public function testDiscoveryNonHttpsMe()
    {
        $discovery = new Discovery();
        $discoveryResponse = $discovery->discover('http://www.tuxed.net/fkooman/');
    }

    public function testDiscoveryRedirect()
    {
        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    302,
                    array(
                        'Content-Type' => 'text/html',
                        'Location' => 'https://example.org/foo',
                    )
                ),
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

        $discovery = new Discovery($client);
        $discoveryResponse = $discovery->discover('https://www.tuxed.net/fkooman/');
        $this->assertEquals('https://indiecert.net/auth', $discoveryResponse->getAuthorizationEndpoint());
        $this->assertEquals('https://indiecert.net/token', $discoveryResponse->getTokenEndpoint());
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage Redirect URL, http://example.org/foo, does not use one of the allowed redirect protocols: https
     */
    public function testDiscoveryRedirectToHttp()
    {
        $client = new Client();
        $mock = new Mock(
            array(
                new Response(
                    302,
                    array(
                        'Content-Type' => 'text/html',
                        'Location' => 'http://example.org/foo',
                    )
                ),
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

        $discovery = new Discovery($client);
        $discoveryResponse = $discovery->discover('https://www.tuxed.net/fkooman/');
    }
}

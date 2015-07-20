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

use DomDocument;
use GuzzleHttp\Client;
use GuzzleHttp\Url;
use InvalidArgumentException;

/**
 * Discover the user's "authorization_endpoint" and "token_endpoint" on their
 * home page.
 */
class Discovery
{
    /** @var \GuzzleHttp\Client */
    private $client;

    public function __construct(Client $client = null)
    {
        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
    }

    /**
     * @return DiscoveryResponse
     */
    public function discover($me)
    {
        $me = self::validateUrl($me);
        $homePage = $this->fetchUrl($me);
        $relLinks = $this->extractRelLinks($homePage);

        $authorizationEndpoint = $this->getLink($relLinks, 'authorization_endpoint');
        // FIXME: we should follow and make sure it doesn't redirect to
        // http URLs and exports IndieAuth: authorization_endpoint header

        $tokenEndpoint = $this->getLink($relLinks, 'token_endpoint');
        // FIXME: we should follow and make sure it doesn't redirect to
        // http URLs

        return new DiscoveryResponse(
            $authorizationEndpoint,
            $tokenEndpoint
        );
    }

    private function getLink(array $relLinks, $link)
    {
        if (array_key_exists($link, $relLinks)) {
            $link = self::validateUrl($relLinks[$link]);

            return $link;
        }

        return;
    }

    private function fetchUrl($pageUrl)
    {
        // do not allow redirects to http URLs
        return $this->client->get(
            $pageUrl,
            array(
                'allow_redirects' => array(
                    'protocols' => array('https'),
                ),
            )
        )->getBody();
    }

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

    private function validateUrl($urlStr)
    {
        if (false === filter_var($urlStr, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException('invalid URL');
        }
        if (0 !== stripos($urlStr, 'https://')) {
            throw new InvalidArgumentException('URL must be a valid https URL');
        }

        return $urlStr;
    }
}

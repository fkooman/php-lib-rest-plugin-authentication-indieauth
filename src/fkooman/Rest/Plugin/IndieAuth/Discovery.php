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

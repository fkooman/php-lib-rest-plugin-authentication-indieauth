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
use DomainException;
use RuntimeException;
use fkooman\Http\Uri;
use GuzzleHttp\Subscriber\History;
use GuzzleHttp\Url;
use DomDocument;

/**
 * Discover the user's "authorization_endpoint" and "token_endpoint" on their
 * home page.
 */
class Discovery
{
    /** @var GuzzleHttp\Client */
    private $client;

    public function __construct(Client $client = null)
    {
        if (null === $client) {
            $client = new Client();
        }
        $this->client = $client;
        $this->fetchCache = null;
    }

    /**
     * @return DiscoveryResponse
     */
    public function discover($me)
    {
        $me = Discovery::validateUri($me);

        $homePage = $this->fetchUri($me);

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
            $link = Discovery::validateUri($relLinks[$link]);
            return $link;
        }

        return null;
    }

    private function fetchUri($pageUri)
    {
        // we track all URLs on the redirect path (if any) and make sure none
        // of them redirect to a HTTP URL. Unfortunately Guzzle 3/4 can not do
        // this by default but we need this "hack". This is fixed in Guzzle 5+
        // see https://github.com/guzzle/guzzle/issues/841
        $history = new History();
        $this->client->getEmitter()->attach($history);

        $request = $this->client->createRequest('GET', $pageUri);
        $response = $this->client->send($request);

        foreach ($history as $transaction) {
            $u = Url::fromString($transaction['request']->getUrl());
            if ('https' !== $u->getScheme()) {
                throw new RuntimeException('redirect path contains non-HTTPS URLs');
            }
        }

        return $response->getBody();
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

    private function validateUri($uriStr)
    {
        $uriObj = new Uri($uriStr);
        if ('https' !== $uriObj->getScheme()) {
            throw new DomainException('uri must be a valid https URL');
        }
        return $uriObj->getUri();
    }
}

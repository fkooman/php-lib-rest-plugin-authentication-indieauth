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

use fkooman\Http\Exception\BadRequestException;

class InputValidation
{
    public static function validateState($state)
    {
        if (null === $state) {
            throw new BadRequestException('missing parameter "state"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $state)) {
            throw new BadRequestException('"state" contains invalid characters');
        }

        return $state;
    }

    public static function validateCode($code)
    {
        if (null === $code) {
            throw new BadRequestException('missing parameter "code"');
        }
        if (1 !== preg_match('/^(?:[\x20-\x7E])*$/', $code)) {
            throw new BadRequestException('"code" contains invalid characters');
        }

        return $code;
    }

    public static function validateRedirectTo($rootUrl, $redirectTo)
    {
        // no redirectTo specified
        if (null === $redirectTo) {
            $redirectTo = $rootUrl;
        }

        // redirectTo specified, using path relative to absRoot
        if (0 === strpos($redirectTo, '/')) {
            $redirectTo = $rootUrl.substr($redirectTo, 1);
        }

        if (false === filter_var($redirectTo, FILTER_VALIDATE_URL)) { //, FILTER_FLAG_PATH_REQUIRED)) {
            throw new BadRequestException(sprintf('invalid redirect_to URL "%s"', $redirectTo));
        }

        // URL needs to start with absRoot
        if (0 !== strpos($redirectTo, $rootUrl)) {
            throw new BadRequestException('redirect_to needs to point to a URL relative to the application root');
        }

        return $redirectTo;
    }

    public static function validateMe($me)
    {
        if (null === $me) {
            throw new BadRequestException('missing parameter "me"');
        }
        if (0 !== stripos($me, 'http')) {
            $me = sprintf('https://%s', $me);
        }

        if (false === filter_var($me, FILTER_VALIDATE_URL)) {
            throw new BadRequestException('"me" is an invalid URL');
        }

        if ('https' !== parse_url($me, PHP_URL_SCHEME)) {
            throw new BadRequestException('"me" MUST be a https URL');
        }

        if (null !== parse_url($me, PHP_URL_QUERY)) {
            throw new BadRequestException('"me" MUST NOT contain query parameters');
        }

        if (null !== parse_url($me, PHP_URL_FRAGMENT)) {
            throw new BadRequestException('"me" MUST NOT contain fragment');
        }

        // if no path is set, add '/'
        if (null === parse_url($me, PHP_URL_PATH)) {
            $me .= '/';
        }

        return $me;
    }

    public static function validateScope($scope)
    {
        // allow no scope as well
        if (null === $scope) {
            return;
        }

        if (!is_string($scope)) {
            throw new BadRequestException('scope must be string');
        }

        if (0 >= strlen($scope)) {
            throw new BadRequestException('scope must not be empty');
        }

        $scopeTokens = explode(' ', $scope);
        foreach ($scopeTokens as $token) {
            self::validateScopeToken($token);
        }
        sort($scopeTokens, SORT_STRING);

        return implode(' ', array_values(array_unique($scopeTokens, SORT_STRING)));
    }

    private static function validateScopeToken($scopeToken)
    {
        if (!is_string($scopeToken) || 0 >= strlen($scopeToken)) {
            throw new BadRequestException('scope token must be a non-empty string');
        }
        if (1 !== preg_match('/^(?:\x21|[\x23-\x5B]|[\x5D-\x7E])+$/', $scopeToken)) {
            throw new BadRequestException('invalid characters in scope token');
        }
    }
}

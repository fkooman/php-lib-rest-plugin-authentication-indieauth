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

use InvalidArgumentException;

class IO
{
    /** @var int */
    private $randomLength;

    public function __construct($randomLength = 16)
    {
        $l = intval($randomLength);
        if (8 > $l) {
            throw new InvalidArgumentException('random length MUST be at least 8');
        }
        $this->randomLength = $l;
    }

    public function getRandomHex()
    {
        return bin2hex(
            openssl_random_pseudo_bytes(
                $this->randomLength
            )
        );
    }
}

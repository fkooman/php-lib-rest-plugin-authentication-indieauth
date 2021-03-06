<?php

/**
 *  Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace fkooman\Rest\Plugin\Authentication\IndieAuth\Test;

use fkooman\Tpl\TemplateManagerInterface;
use fkooman\Json\Json;

class TestTemplateManager implements TemplateManagerInterface
{
    public function addDefault(array $templateVariables)
    {
    }

    public function setDefault(array $templateVariables)
    {
    }

    public function render($templateName, array $templateVariables = array())
    {
        return Json::encode(
            array(
                $templateName => $templateVariables,
            )
        );
    }
}

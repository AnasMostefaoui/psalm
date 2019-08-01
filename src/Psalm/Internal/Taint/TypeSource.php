<?php

namespace Psalm\Internal\Taint;

class TypeSource
{
    /** @var \Psalm\Type\Union */
    public $source_type;

    /** @var ?string */
    public $method_id = null;

    public function __construct(\Psalm\Type\Union $source_type)
    {
        $this->source_type = $source_type;
    }
}

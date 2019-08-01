<?php

namespace Psalm\Internal\Taint;

class TypeSource
{
    /** @var string */
    public $method_id;

    /** @var ?int */
    public $argument_offset = null;

    /** @var bool   */
    public $from_return_type;

    public function __construct(string $method_id, ?int $argument_offset, bool $from_return_type)
    {
        $this->method_id = $method_id;
        $this->argument_offset = $argument_offset;
        $this->from_return_type = $from_return_type;
    }
}

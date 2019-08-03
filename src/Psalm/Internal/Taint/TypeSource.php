<?php

namespace Psalm\Internal\Taint;

use Psalm\CodeLocation;

class TypeSource
{
    /** @var string */
    public $method_id;

    /** @var ?int */
    public $argument_offset = null;

    /** @var bool   */
    public $from_return_type;

    /** @var ?CodeLocation */
    public $code_location;

    public function __construct(string $method_id, ?int $argument_offset, bool $from_return_type, ?CodeLocation $code_location)
    {
        $this->method_id = strtolower($method_id);
        $this->argument_offset = $argument_offset;
        $this->from_return_type = $from_return_type;
        $this->code_location = $code_location;
    }

    public function __toString() {
        return $this->method_id . ':' . $this->argument_offset . ':' . $this->from_return_type;
    }
}

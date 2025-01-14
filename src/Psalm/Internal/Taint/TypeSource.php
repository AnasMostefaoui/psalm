<?php

namespace Psalm\Internal\Taint;

use Psalm\CodeLocation;

class TypeSource
{
    /** @var string */
    public $id;

    /** @var ?CodeLocation */
    public $code_location;

    public function __construct(string $id, ?CodeLocation $code_location)
    {
        $this->id = $id;
        $this->code_location = $code_location;
    }

    public static function getForMethodArgument(
        string $method_id,
        int $argument_offset,
        ?CodeLocation $code_location
    ) : self {
        return new self(\strtolower($method_id . '#' . ($argument_offset + 1)), $code_location);
    }

    public function __toString()
    {
        return $this->id;
    }
}

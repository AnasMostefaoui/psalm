<?php

namespace Psalm\Internal\Codebase;

use Psalm\CodeLocation;
use Psalm\Internal\Analyzer\StatementsAnalyzer;
use Psalm\Internal\Taint\TypeSource;
use Psalm\IssueBuffer;
use Psalm\Issue\TaintedInput;
use function array_merge;
use function array_merge_recursive;
use function strtolower;
use UnexpectedValueException;

class Taint
{
    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $new_param_sinks = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $new_return_sinks = [];

    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $new_param_sources = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $new_return_sources = [];

    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $previous_param_sinks = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $previous_return_sinks = [];

    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $previous_param_sources = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $previous_return_sources = [];

    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $archived_param_sinks = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $archived_return_sinks = [];

    /**
     * @var array<string, array<int, ?TypeSource>>
     */
    private $archived_param_sources = [];

    /**
     * @var array<string, ?TypeSource>
     */
    private $archived_return_sources = [];

    public function hasExistingSink(TypeSource $source) : ?TypeSource
    {
        if ($source->argument_offset !== null) {
            return $this->archived_param_sinks[$source->method_id][$source->argument_offset] ?? null;
        }

        if ($source->from_return_type) {
            return $this->archived_return_sinks[$source->method_id] ?? null;
        }

        return null;
    }

    public function hasNewOrExistingSink(TypeSource $source) : ?TypeSource
    {
        if ($source->argument_offset !== null) {
            return $this->new_param_sinks[$source->method_id][$source->argument_offset]
                ?? $this->archived_param_sinks[$source->method_id][$source->argument_offset]
                ?? null;
        }

        if ($source->from_return_type) {
            return $this->new_return_sinks[$source->method_id]
                ?? $this->archived_return_sinks[$source->method_id]
                ?? null;
        }

        return null;
    }

    public function hasPreviousSink(TypeSource $source) : bool
    {
        if ($source->argument_offset !== null) {
            return isset($this->previous_param_sinks[$source->method_id][$source->argument_offset]);
        }

        if ($source->from_return_type) {
            return isset($this->previous_return_sinks[$source->method_id]);
        }

        return false;
    }

    public function hasPreviousSource(TypeSource $source) : bool
    {
        if ($source->argument_offset !== null) {
            return isset($this->previous_param_sources[$source->method_id][$source->argument_offset]);
        }

        if ($source->from_return_type) {
            return isset($this->previous_return_sources[$source->method_id]);
        }

        return false;
    }

    public function hasExistingSource(TypeSource $source) : ?TypeSource
    {
        if ($source->argument_offset !== null) {
            return $this->archived_param_sources[$source->method_id][$source->argument_offset] ?? null;
        }

        if ($source->from_return_type) {
            return $this->archived_return_sources[$source->method_id] ?? null;
        }

        return null;
    }

    public function hasNewOrExistingSource(TypeSource $source) : ?TypeSource
    {
        if ($source->argument_offset !== null) {
            return $this->new_param_sources[$source->method_id][$source->argument_offset]
                ?? $this->archived_param_sources[$source->method_id][$source->argument_offset]
                ?? null;
        }

        if ($source->from_return_type) {
            return $this->new_return_sources[$source->method_id]
                ?? $this->archived_return_sources[$source->method_id]
                ?? null;
        }

        return null;
    }

    /**
     * @param array<TypeSource> $sources
     */
    public function addSources(
        StatementsAnalyzer $statements_analyzer,
        array $sources,
        \Psalm\CodeLocation $code_location,
        ?TypeSource $previous_source
    ) : void {
        foreach ($sources as $source) {
            if ($this->hasExistingSource($source)) {
                continue;
            }

            if (($next_source = $this->hasExistingSink($source))
                && (!$previous_source || (string) $previous_source === (string) $next_source)
            ) {
                if (IssueBuffer::accepts(
                    new TaintedInput(
                        ($previous_source ? 'in path ' . $this->getPredecessorPath($previous_source) : '')
                            . ' out path ' . $this->getSuccessorPath($source),
                        $code_location
                    ),
                    $statements_analyzer->getSuppressedIssues()
                )) {
                    // fall through
                }
            }

            if ($source->argument_offset !== null) {
                $this->new_param_sources[$source->method_id][$source->argument_offset] = $previous_source;
            }

            if ($source->from_return_type) {
                $this->new_return_sources[$source->method_id] = $previous_source;
            }

        }
    }

    public function getPredecessorPath(TypeSource $source) : string
    {
        if ($source->argument_offset !== null) {
            $source_descriptor = $source->method_id . ' arg ' . ($source->argument_offset + 1)
                . ($source->code_location ? ' (' . $source->code_location->getShortSummary() . ')' : '');

            if ($previous_source
                = $this->new_param_sources[$source->method_id][$source->argument_offset]
                    ?? $this->archived_param_sources[$source->method_id][$source->argument_offset]
                    ?? null
            ) {
                if ($previous_source === $source) {
                    throw new \UnexpectedValueException('bad');
                }
                return $this->getPredecessorPath($previous_source) . ' -> ' . $source_descriptor;
            }

            return $source_descriptor;
        }

        if ($source->from_return_type) {
            $source_descriptor = $source->method_id . ' return type'
                . ($source->code_location ? ' (' . $source->code_location->getShortSummary() . ')' : '');

            if ($previous_source
                = $this->new_return_sources[$source->method_id]
                    ?? $this->archived_return_sources[$source->method_id]
                    ?? null
            ) {
                return $this->getPredecessorPath($previous_source) . ' -> ' . $source_descriptor;
            }

            return $source_descriptor;
        }

        return '';
    }

    public function getSuccessorPath(TypeSource $source) : string
    {
        if ($source->argument_offset !== null) {
            $source_descriptor = $source->method_id . ' arg ' . ($source->argument_offset + 1)
                . ($source->code_location ? ' (' . $source->code_location->getShortSummary() . ')' : '');

            if ($next_source
                = $this->new_param_sinks[$source->method_id][$source->argument_offset]
                    ?? $this->archived_param_sinks[$source->method_id][$source->argument_offset]
                    ?? null
            ) {
                return $source_descriptor . ' -> ' . $this->getSuccessorPath($next_source);
            }

            return $source_descriptor;
        }

        if ($source->from_return_type) {
            $source_descriptor = $source->method_id . ' return value'
                . ($source->code_location ? ' (' . $source->code_location->getShortSummary() . ')' : '');

            if ($next_source
                = $this->new_return_sinks[$source->method_id]
                    ?? $this->archived_return_sinks[$source->method_id]
                    ?? null
            ) {
                return $source_descriptor . ' -> ' .$this->getSuccessorPath($next_source);
            }

            return $source_descriptor;
        }

        return '';
    }

    /**
     * @param array<TypeSource> $sources
     */
    public function addSinks(
        StatementsAnalyzer $statements_analyzer,
        array $sources,
        \Psalm\CodeLocation $code_location,
        ?TypeSource $previous_source
    ) : void {
        foreach ($sources as $source) {
            if ($this->hasExistingSink($source)) {
                continue;
            }

            if ($next_source = $this->hasExistingSource($source)) {
                if (IssueBuffer::accepts(
                    new TaintedInput(
                        'in path ' . $this->getPredecessorPath($source)
                            . ($previous_source ? ' out path ' . $this->getSuccessorPath($previous_source) : ''),
                        $code_location
                    ),
                    $statements_analyzer->getSuppressedIssues()
                )) {
                    // fall through
                }
            }

            if ($source->argument_offset !== null) {
                $this->new_param_sinks[$source->method_id][$source->argument_offset] = $previous_source;
            }

            if ($source->from_return_type) {
                $this->new_return_sinks[$source->method_id] = $previous_source;
            }
        }
    }

    public function hasNewSinksAndSources() : bool
    {
        /*echo count($this->new_param_sinks)
            . ' ' . count($this->new_return_sinks)
            . ' ' . count($this->new_param_sources)
            . ' ' . count($this->new_return_sources)
            . "\n\n"; */
        return ($this->new_param_sinks || $this->new_return_sinks)
            && ($this->new_param_sources || $this->new_return_sources);
    }

    public function addThreadData(self $taint) : void
    {
        $this->new_param_sinks = array_merge_recursive(
            $this->new_param_sinks,
            $taint->new_param_sinks
        );

        $this->new_param_sources = array_merge_recursive(
            $this->new_param_sources,
            $taint->new_param_sources
        );

        $this->new_return_sinks = array_merge(
            $this->new_return_sinks,
            $taint->new_return_sinks
        );

        $this->new_return_sources = array_merge(
            $this->new_return_sources,
            $taint->new_return_sources
        );
    }

    public function clearNewSinksAndSources() : void
    {
        $this->archived_param_sinks = array_merge_recursive(
            $this->archived_param_sinks,
            $this->new_param_sinks
        );

        $this->archived_return_sinks = array_merge(
            $this->archived_return_sinks,
            $this->new_return_sinks
        );

        $this->previous_param_sinks = $this->new_param_sinks;
        $this->previous_return_sinks = $this->new_return_sinks;

        $this->new_param_sinks = [];
        $this->new_return_sinks = [];

        $this->archived_param_sources = array_merge_recursive(
            $this->archived_param_sources,
            $this->new_param_sources
        );

        $this->archived_return_sources = array_merge(
            $this->archived_return_sources,
            $this->new_return_sources
        );

        $this->previous_param_sources = $this->new_param_sources;
        $this->previous_return_sources = $this->new_return_sources;

        $this->new_param_sources = [];
        $this->new_return_sources = [];
    }
}

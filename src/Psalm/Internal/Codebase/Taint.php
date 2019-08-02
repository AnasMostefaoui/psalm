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
            return $this->archived_param_sinks[strtolower($source->method_id)][$source->argument_offset]
                ?? ($this->previous_param_sinks[strtolower($source->method_id)][$source->argument_offset]
                ?? null);
        }

        if ($source->from_return_type) {
            return $this->archived_return_sinks[strtolower($source->method_id)]
                ?? ($this->previous_return_sinks[strtolower($source->method_id)]
                ?? null);
        }

        return null;
    }

    public function hasPreviousSink(TypeSource $source) : bool
    {
        if ($source->argument_offset !== null) {
            return isset($this->previous_param_sinks[strtolower($source->method_id)][$source->argument_offset]);
        }

        if ($source->from_return_type) {
            return isset($this->previous_return_sinks[strtolower($source->method_id)]);
        }

        return false;
    }

    public function hasPreviousSource(TypeSource $source) : bool
    {
        if ($source->argument_offset !== null) {
            return isset($this->previous_param_sources[strtolower($source->method_id)][$source->argument_offset]);
        }

        if ($source->from_return_type) {
            return isset($this->previous_return_sources[strtolower($source->method_id)]);
        }

        return false;
    }

    public function hasExistingSource(TypeSource $source) : ?TypeSource
    {
        if ($source->argument_offset !== null) {
            return $this->archived_param_sources[strtolower($source->method_id)][$source->argument_offset]
                ?? $this->previous_param_sources[strtolower($source->method_id)][$source->argument_offset]
                ?? null;
        }

        if ($source->from_return_type) {
            return $this->archived_return_sources[strtolower($source->method_id)]
                ?? $this->previous_return_sources[strtolower($source->method_id)]
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

            if ($next_source = $this->hasExistingSink($source)) {
                if (IssueBuffer::accepts(
                    new TaintedInput(
                        'Something is bad here ' . $next_source->method_id,
                        $code_location
                    ),
                    $statements_analyzer->getSuppressedIssues()
                )) {
                    // fall through
                }
            }

            if ($source->argument_offset !== null) {
                $this->new_param_sources[strtolower($source->method_id)][$source->argument_offset] = $previous_source;
            }

            if ($source->from_return_type) {
                $this->new_return_sources[strtolower($source->method_id)] = $previous_source;
            }
        }
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
                        'Something is bad here ' . $next_source->method_id,
                        $code_location
                    ),
                    $statements_analyzer->getSuppressedIssues()
                )) {
                    // fall through
                }
            }

            if ($source->argument_offset !== null) {
                $this->new_param_sinks[strtolower($source->method_id)][$source->argument_offset] = $previous_source;
            }

            if ($source->from_return_type) {
                $this->new_return_sinks[strtolower($source->method_id)] = $previous_source;
            }
        }
    }

    public function hasNewSinksAndSources() : bool
    {
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

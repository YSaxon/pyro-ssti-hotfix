<?php

namespace YSaxon\PyroSstiHotfix;

/**
 * Default whitelists for the Twig security policy.
 *
 * These defaults are carefully curated to be SECURE by excluding dangerous
 * features that can lead to RCE, while still allowing common template operations.
 *
 * SECURITY NOTE: The following are deliberately EXCLUDED:
 * - Filters: map, filter, reduce (RCE via callable injection)
 * - Tags: include, extends, block, macro, import, embed, use (template inclusion)
 * - Functions: source (file read), include (template inclusion)
 *
 * @author Yaakov Saxon
 */
class SecurityPolicyDefaults
{
    /**
     * Special token to include defaults in custom arrays.
     * Usage: ['custom_tag', INCLUDE_DEFAULTS] merges custom with defaults.
     */
    public const INCLUDE_DEFAULTS = '(include_defaults)';

    /**
     * Safe Twig tags.
     * Excludes: include, extends, block, macro, import, embed, use
     */
    public const TAGS = [
        'autoescape',
        'apply',      // Replacement for deprecated 'filter' tag
        'do',
        'flush',
        'for',
        'if',
        'set',
        'spaceless',
        'verbatim',
        'with',
        // Deliberately excluded for security:
        // 'include', 'extends', 'block', 'macro', 'import', 'embed', 'use', 'sandbox'
    ];

    /**
     * Safe Twig filters.
     * Excludes: map, filter, reduce (can execute arbitrary callables)
     */
    public const FILTERS = [
        'abs',
        'batch',
        'capitalize',
        'column',
        'convert_encoding',
        'country_name',
        'currency_name',
        'currency_symbol',
        'date',
        'date_modify',
        'default',
        'e',          // Alias for escape
        'escape',
        'first',
        'format',
        'format_currency',
        'format_date',
        'format_datetime',
        'format_number',
        'format_time',
        'join',
        'json_encode',
        'keys',
        'language_name',
        'last',
        'length',
        'locale_name',
        'lower',
        'merge',
        'nl2br',
        'number_format',
        'raw',
        'replace',
        'reverse',
        'round',
        'slice',
        'slug',
        // 'sort',       // Safe without callable argument
        'spaceless',
        'split',
        'striptags',
        'timezone_name',
        'title',
        'trim',
        'upper',
        'url_encode',
        // Deliberately excluded for security (RCE vectors):
        // 'map', 'filter', 'reduce'
    ];

    /**
     * Safe Twig functions.
     */
    public const FUNCTIONS = [
        // 'attribute',
        'block',
        // 'constant',
        'country_names',
        'country_timezones',
        'currency_names',
        'cycle',
        'date',
        // 'dump',       // Useful for debugging, generally safe
        'html_classes',
        'language_names',
        'locale_names',
        'max',
        'min',
        'parent',
        'random',
        'range',
        'script_names',
        'timezone_names',
        // Deliberately excluded:
        // 'source' (reads file contents), 'include' (includes templates)
        // 'template_from_string' (creates templates from strings)
    ];

    /**
     * Safe object methods.
     * Format: ['ClassName' => ['method1', 'method2', ...]]
     * Supports wildcards: 'get*' matches all methods starting with 'get'
     */
    public const METHODS = [
        // Twig's internal classes - required for basic operation
        'Twig\Template' => ['*'],
        'Twig\Markup' => ['*'],

        // Common safe patterns (like Drupal's approach)
        '*' => [
            '__toString',
            'toString',
            'count',
            // Getters are generally safe for read operations
            'get*',
            'has*',
            'is*',
        ],
    ];

    /**
     * Safe object properties.
     * Format: ['ClassName' => ['property1', 'property2', ...]]
     */
    public const PROPERTIES = [
        // By default, allow all properties - they're read-only in templates
        // You can restrict this if needed
        'Twig\Template' => ['*'],
        'Twig\Markup' => ['*'],
    ];

    /**
     * Process defaults token and merge defaults into all arrays.
     *
     * @param array &$tags
     * @param array &$filters
     * @param array &$functions
     * @param array &$methods
     * @param array &$properties
     */
    public static function addDefaultsToAll(
        array &$tags,
        array &$filters,
        array &$functions,
        array &$methods,
        array &$properties
    ): void {
        $tags = self::addDefaultsToIndexedArray($tags, self::TAGS);
        $filters = self::addDefaultsToIndexedArray($filters, self::FILTERS);
        $functions = self::addDefaultsToIndexedArray($functions, self::FUNCTIONS);
        $methods = self::addDefaultsToAssociativeArray($methods, self::METHODS);
        $properties = self::addDefaultsToAssociativeArray($properties, self::PROPERTIES);
    }

    /**
     * Process defaults token for an indexed array.
     *
     * @param array $array The array to process
     * @param array $defaults The defaults to add if token is present
     * @return array The processed array
     */
    public static function addDefaultsToIndexedArray(array $array, array $defaults): array
    {
        if (in_array(self::INCLUDE_DEFAULTS, $array, true)) {
            // Remove the defaults marker
            $array = array_filter($array, fn($v) => $v !== self::INCLUDE_DEFAULTS);
            // Merge with defaults
            $array = array_values(array_unique(array_merge($array, $defaults)));
        }
        return $array;
    }

    /**
     * Process defaults token for an associative array.
     *
     * @param array $array The array to process
     * @param array $defaults The defaults to add if token is present
     * @return array The processed array
     */
    public static function addDefaultsToAssociativeArray(array $array, array $defaults): array
    {
        if (in_array(self::INCLUDE_DEFAULTS, $array, true)) {
            // Remove the defaults marker
            $key = array_search(self::INCLUDE_DEFAULTS, $array, true);
            if ($key !== false) {
                unset($array[$key]);
            }
            // Deep merge with defaults
            $array = self::deepMergeAssociative($defaults, $array);
        }
        return $array;
    }

    /**
     * Deep merge two associative arrays, combining values for matching keys.
     *
     * @param array $array1 First array (defaults)
     * @param array $array2 Second array (overrides/additions)
     * @return array Merged array
     */
    protected static function deepMergeAssociative(array $array1, array $array2): array
    {
        $merged = $array1;

        foreach ($array2 as $key => $value) {
            if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
                // Both are arrays - merge them
                $merged[$key] = array_values(array_unique(
                    array_merge($merged[$key], $value)
                ));
            } else {
                // Override or add new key
                $merged[$key] = $value;
            }
        }

        return $merged;
    }
}

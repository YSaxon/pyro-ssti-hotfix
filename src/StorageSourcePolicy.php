<?php

namespace YSaxon\PyroCmsSstiFix;

use Twig\Sandbox\SourcePolicyInterface;
use Twig\Source;

/**
 * Source policy that enables sandbox for templates loaded from the storage path.
 *
 * In PyroCMS, user-editable templates (from database, admin UI, etc.) are typically
 * stored in the storage directory. This policy sandboxes those templates while
 * leaving legitimate theme/addon templates unrestricted.
 *
 * @author Yaakov Saxon
 */
class StorageSourcePolicy implements SourcePolicyInterface
{
    /**
     * The real (resolved) storage path.
     */
    protected string $storagePath;

    /**
     * Cache for path checks to improve performance.
     */
    protected array $cache = [];

    /**
     * Create a new StorageSourcePolicy instance.
     *
     * @param string $storagePath The path where user-editable templates are stored
     */
    public function __construct(string $storagePath)
    {
        $this->storagePath = rtrim(realpath($storagePath) ?: $storagePath, DIRECTORY_SEPARATOR);
    }

    /**
     * Determine whether the sandbox should be enabled for the given source.
     *
     * Returns true (sandbox ON) for templates from the storage path.
     * Returns false (sandbox OFF) for templates from other locations.
     *
     * @param Source|null $source The template source
     * @return bool True to enable sandbox
     */
    public function enableSandbox(?Source $source): bool
    {
        if ($source === null) {
            // No source info - be safe and don't sandbox
            // (This typically means it's a string template being rendered directly)
            return false;
        }

        $sourcePath = $source->getPath();

        // No path means it's likely a string template or similar
        if (empty($sourcePath)) {
            // String templates without paths should be sandboxed as they're often
            // from dynamic/user content. But we need to be careful here.
            // Check the name for hints
            $name = $source->getName();

            // If it looks like a generated/string template, sandbox it
            if ($this->looksLikeDynamicTemplate($name)) {
                return true;
            }

            return false;
        }

        // Check cache
        if (isset($this->cache[$sourcePath])) {
            return $this->cache[$sourcePath];
        }

        // Resolve to real path for comparison
        $realSourcePath = realpath($sourcePath);

        // If we can't resolve the path, be conservative
        if ($realSourcePath === false) {
            $this->cache[$sourcePath] = false;
            return false;
        }

        // Check if the template is under the storage path
        // $isInStorage = str_starts_with($realSourcePath, $this->storagePath . DIRECTORY_SEPARATOR)
        $isInStorage = (substr($realSourcePath, 0, strlen($this->storagePath) + 1) === $this->storagePath . DIRECTORY_SEPARATOR)
                    || $realSourcePath === $this->storagePath;

        $this->cache[$sourcePath] = $isInStorage;


    \Log::debug('[SandboxPolicy]', [
        'path' => $sourcePath,
        'isInStorage' => $isInStorage,
    ]);

        return $isInStorage;
    }

    /**
     * Check if a template name looks like a dynamically generated template.
     *
     * @param string $name The template name
     * @return bool True if it appears to be dynamic
     */
    protected function looksLikeDynamicTemplate(string $name): bool
    {
        // Common patterns for string/dynamic templates
        $dynamicPatterns = [
            '/^__string_template__/',  // Twig's internal string template name
            '/^[a-f0-9]{32,}$/',       // Hash-like names
            '/^\d+$/',                  // Numeric IDs
        ];

        foreach ($dynamicPatterns as $pattern) {
            if (preg_match($pattern, $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the storage path being used.
     *
     * @return string
     */
    public function getStoragePath(): string
    {
        return $this->storagePath;
    }

    /**
     * Clear the internal cache.
     *
     * @return void
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }
}

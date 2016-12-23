<?php

/**
 * This configuration will be read and overlaid on top of the
 * default configuration. Command line arguments will be applied
 * after this file is read.
 */
return [
    'quick_mode' => false,
    'processes' => 2,
    'analyze_signature_compatibility' => true,
    'dead_code_detection' => true,
    'minimum_severity' => Issue::SEVERITY_CRITICAL,
    'directory_list' => [
        'src',
        'vendor/league/uri',
        'vendor/nesbot/carbon',
        'vendor/phpseclib/phpseclib'
    ],
    "exclude_analysis_directory_list" => [
        'vendor/'
    ],
];

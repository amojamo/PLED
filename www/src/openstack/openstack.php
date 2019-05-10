<?php
use Aws\S3\S3Client;

/**
*
*   Open Stack config
*
**/
$ini_array = parse_ini_file($_SERVER['DOCUMENT_ROOT']."/conf/phpconfig.ini", true);
$s3 = new S3Client([
    'region' => $ini_array['s3_region'],
    'endpoint' => $ini_array['s3_endpoint'],
    'version' => 'latest',
    'credentials' => [
        'key' => $ini_array['s3_key'],
        'secret' => $ini_array['s3_secret'],
    ],
    'use_path_style_endpoint' => true,
]);

return $s3;
<?php

require_once "../vendor/autoload.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;

$_GET['filepath'];
$filename = str_replace(' ', '_', $_GET['name']);
$s3 = include 'openstack/openstack.php';

$cmd = $s3->getCommand('GetObject', [
        'Bucket' => 'pled_files',
        'Key'    => $_GET['filepath']
]);
$signed_url = $s3->createPresignedRequest($cmd, '+1 hour');
echo 'Download url: '.$signed_url->getUri() . "\n";


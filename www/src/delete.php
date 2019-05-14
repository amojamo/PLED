<?php
require_once "../vendor/autoload.php";
require_once "../src/classes/Api.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
$ini_array = parse_ini_file("../conf/phpconfig.ini", true);


$api = new Api($ini_array);
$res = $api->delete($_GET['id'], $_GET['type']);
$obj = json_decode($res['response'], true);
var_dump($obj);
// Check for errors
if($res['response'] === FALSE){
    die($res['error']);
    $data['response'] = 'Something is wrong, check DreamFactory configurations';
    echo $twig->render('databaseManagementPage.html', $data); // Render html
}

if ($res['response'] != FALSE) {
    $s3 = include 'openstack/openstack.php';
    try{
        $r = $s3->deleteObject([
            'Bucket' => 'pled_files/'.$_GET['type'],
            'Key' => $res['file_path']
        ]);
    } catch (S3Exception $e) {
        echo $e->getMessage() . PHP_EOL;
        $data['error'] = 's3Exeption';
        echo $twig->render('databaseManagementPage.html', $data); // Render html
    }
}

// TODO Find do error handling on response code.
if (!empty($obj['error']['code']) && ($obj['error']['code'] != 200) && (!$r['DeleteMarker'])) {
    $data['deleted'] = 'false';
} else {
    $data['deleted'] = 'true';
} 
header('Location: ../index.php?deleted=' . $data['deleted']);
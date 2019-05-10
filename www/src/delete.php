<?php
require_once "../vendor/autoload.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;

var_dump($_GET);

$ini_array = parse_ini_file("../conf/phpconfig.ini", true);

$dfapikey = 'X-DreamFactory-API-Key:'.$ini_array["api_key"];

$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/'.$_GET['type'].'/'.$_GET['id'].'?fields=file_path&api_key='.$ini_array["api_key"]);
$file_path = json_decode($json, true);

$ch = curl_init();
$options = array(CURLOPT_URL => 'http://10.212.137.92/api/v2/mongodb/_table/'.$_GET['type'].'/'.$_GET['id'], 
	CURLOPT_HTTPHEADER => array($dfapikey, 'Content-Type: application/json'),
	CURLOPT_CUSTOMREQUEST => 'DELETE'
    );
    //http://10.212.137.92/api/v2/mongodb/_table/vuln_applications?fields=file_path

    curl_setopt_array($ch, $options);
    print_r($options);
    // Send the request
    $response = curl_exec($ch);
    $obj = json_decode($response, true);
    

    // Check for errors
    if($response === FALSE){
        die(curl_error($ch));
        $data['response'] = 'Something is wrong, check DreamFactory configurations';
        echo $twig->render('databaseManagementPage.html', $data); // Render html
    }

    if ($response != FALSE) {
        $s3 = include 'openstack/openstack.php';
        try{
            $r = $s3->deleteObject([
                'Bucket' => 'pled_files/'.$_GET['type'],
                'Key' => $file_path['file_path']
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
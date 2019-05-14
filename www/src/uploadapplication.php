<?php
require_once "../vendor/autoload.php";
require_once "../src/classes/Api.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;

// Set up Twig loader system
$loader = new Twig_Loader_Filesystem('../views');
$twig   = new Twig_Environment($loader, array());
$ini_array = parse_ini_file("../conf/phpconfig.ini", true);

$api = new Api($ini_array);
$collections = explode(',', $ini_array['collections']);
foreach($collections as $collection){
	$data[$collection] = $api->getContents($collection);
}

/**
*
*    Check if application name and file is set,
*    return error messages and marks fields if not 
*
**/
if(!empty($_POST['app_cve'])) {
    $json = file_get_contents('http://cve.circl.lu/api/cve/' . $_POST['app_cve']);
}
if (empty($_POST['app_name']) || empty($_FILES['app_fileToUpload']['tmp_name']) || $json == 'null') {
    $data['errmsg'] = "Some fields needs to be filled";
    if (empty($_POST['app_name'])) {
        $data['errname'] = "errborder"; 
    } else {
        $data['app_name'] = $_POST['app_name'];
    }
    if (empty($_FILES['app_fileToUpload']['tmp_name'])) {
        $data['errfile'] = "errborderfile"; 
    } else {
        $data['app_fileToUpload'] = $_POST['app_fileToUpload'];
    }
    /**
    *
    *   If CVE isset, check if valid in circl and return error if not
    *
    **/
    if(!empty($_POST['app_cve'])) {
        $json = file_get_contents('http://cve.circl.lu/api/cve/' . $_POST['app_cve']);
        if ($json != 'null') {
            $data['cve'] = $_POST['app_cve'];
        } else {
            $data['errcve'] = "errborder";
            $data['placeholdercve'] = "Could not find this CVE in CIRCL";
        }
    }
    
    if(!empty($_POST['app_summary'])) {
        $data['app_summary'] = $_POST['app_summary'];
    }

    $data['app_platform'] = $_POST['app_platform'];

    $data['app_tag'] = $_POST['app_tag'];

    echo $twig->render('databaseManagementPage.html', $data); // Render html
} 
/**
*
*   If everything is set, we can insert the application to swift and mongodb
*
*   Stores:
*     cve data:
*       - cve
*       - cwe
*       - published_date
*       - impact
*       - vulnerable_configuration
*       - css
*       - cve_summary
*     
*     application data:
*       - application_name
*       - summary
*       - category
*       - platform
*       - tag
*       - application name in swift
*
*   later, posibility to add uploader/instructor name and/or id 
**/  
else {
    /** Get Open Stack config **/
    
    $s3 = include 'openstack/openstack.php';

    /**
    *
    *   File upload to swift container.
    *   Hashed through md5 the filename and a timestamp becomes the id of the mongod document.
    *   to see in swift: swift list TestContainer in cmd
    *
    **/

    $files = [];
    $content = file_get_contents($_FILES['app_fileToUpload']['tmp_name']);
    //$filename = hash('md5', $_FILES['app_fileToUpload']['name'].date_timestamp_get(date_create()));
    //$path = $_FILES['app_fileToUpload']['name'];
    //$fileext = pathinfo($path, PATHINFO_EXTENSION);
    //$filename = $filename.'.'.$fileext;
    $filename = uniqid().'_'.$_FILES['app_fileToUpload']['name'];
    array_push($files, $filename);

    try{
        $r = $s3->putObject([
            'Bucket' => 'pled_files/vuln_applications',
            'Key' => $filename,
            'Body' => $content
        ]);

        //echo "Application file uploaded to Swift";

        /* API post request */
        $json = '{}';
        $resource = json_decode($json);
        $resource->resource = [];
        $application_to_add = json_decode($json);
        if(!empty($_POST['app_cve'])) {
            $json = file_get_contents('http://cve.circl.lu/api/cve/' . $_POST['app_cve']);
            if($json != 'null') {
                $json_data = json_decode($json, true);
                $application_to_add->cve = $_POST['app_cve'];
                $application_to_add->cve_summary = $json_data['summary'];
                $application_to_add->cvss = $json_data['cvss'];
                $application_to_add->cwe = $json_data['cwe'];
                $application_to_add->published_date = $json_data['Published'];
                $application_to_add->impact = $json_data['impact'];
                $application_to_add->vulnerable_configuration = $json_data['vulnerable_configuration_cpe_2_2'];
            }
        }
        
        $application_to_add->application_name = $_POST['app_name'];
        if (!empty($_POST['app_summary']))
            $application_to_add->summary = $_POST['app_summary'];
        if ($_POST['app_platform'] != "any")
            $application_to_add->platform = $_POST['app_platform'];
        if ($_POST['app_tag'] != "none")
            $application_to_add->tag = $_POST['app_tag'];
        $application_to_add->file_path = $filename;

        $resource->resource[0] = $application_to_add;


        $api = new Api($ini_array);
        $body = json_encode($resource, true);
        $res = $api->insert($body, 'vuln_applications');
        $obj = json_decode($res['response'], true);
        // Check for errors
        if($res['response'] === FALSE){
            die($res['error']);
            $data['error'] = 'dferror';
            echo $twig->render('databaseManagementPage.html', $data); // Render html
        }

        // TODO Find do error handling on response code.
        if (!empty($obj['error']['code']) && ($obj['error']['code'] != 200)) {
            $data['uploaded'] = 'false';
        } else {
            $data['uploaded'] = 'true';
        } 

        header('Location: ../index.php?uploaded=' . $data['uploaded']);
    } catch (S3Exception $e) {
        echo $e->getMessage() . PHP_EOL;
        $data['error'] = 's3Exeption';
        echo $twig->render('databaseManagementPage.html', $data); // Render html
    }
}
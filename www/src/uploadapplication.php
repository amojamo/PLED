<?php
require_once "../vendor/autoload.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;

// Set up Twig loader system
$loader = new Twig_Loader_Filesystem('../views');
$twig   = new Twig_Environment($loader, array());
$ini_array = parse_ini_file("../conf/phpconfig.ini", true);

// Get contents from database '.$ini_array["ip"].'

// Vuln_applications
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['vuln_applications'] = [];
foreach ($obj['resource'] as $key => $v) {
    $data['vuln_applications'][$key]["_id"] = $v['_id'];
    $data['vuln_applications'][$key]["application_name"] = $v['application_name'];
    if(isset($v['exploitdb_id'])) {
        $data['vuln_applications'][$key]["exploitdb_id"] = $v['exploitdb_id'];
    }
    if(isset($v['type'])) {
        $data['vuln_applications'][$key]["type"] = $v['type'];
    }
    if(isset($v['platform'])) {
        $data['vuln_applications'][$key]["platform"] = $v['platform'];
    }
    if(isset($v['published_date'])) {
        $data['vuln_applications'][$key]["published_date"] = $v['published_date'];
    }
    if(isset($v['added_date'])) {
        $data['vuln_applications'][$key]["added_date"] = $v['added_date'];
    }
    $data['vuln_applications'][$key]["cve"] = $v['cve'];
    if(isset($v['cve_summary'])) {
        $data['vuln_applications'][$key]["cve_summary"] = $v['cve_summary'];
    }
    if(isset($v['cwe'])) {
        $data['vuln_applications'][$key]["cwe"] = $v['cwe'];
    }
    if(isset($v['impact'])) {
        $data['vuln_applications'][$key]["impact"] = $v['impact'];
    }
    if(isset($v['vulnerable_configuration'])) {
        $data['vuln_applications'][$key]["vulnerable_configuration"] = $v['vulnerable_configuration'];
    }
    if(isset($v['file_path'])) {
        $data['vuln_applications'][$key]["file_path"] = $v['file_path'];
    }
    if(isset($v['summary'])) {
        $data['vuln_applications'][$key]["summary"] = $v['summary'];
    }
    if(isset($v['tag'])) {
        $data['vuln_applications'][$key]["tag"] = $v['tag'];
    }
}

// ctf_challenges
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['ctf_challenges'] = [];
foreach ($obj['resource'] as $key => $v) {
    $data['ctf_challenges'][$key]["_id"] = $v['_id'];
    $data['ctf_challenges'][$key]["name"] = $v['name'];
    if(isset($v['summary'])) {
        $data['ctf_challenges'][$key]["summary"] = $v['summary'];
    }
    if(isset($v['author'])) {
        $data['ctf_challenges'][$key]["author"] = $v['author'];
    }
    if(isset($v['creation_date'])) {
        $data['ctf_challenges'][$key]["creation_date"] = $v['creation_date'];
    }
    if(isset($v['port'])) {
        $data['ctf_challenges'][$key]['port'] = $v['port'];
    }
    if(isset($v['type'])){
        $data['ctf_challenges'][$key]['type'] = $v['type'];
    }
    if(isset($v['difficulty'])) {
        $data['ctf_challenges'][$key]['difficulty'] = $v['difficulty'];
    }
    if(isset($v['added_date'])) {
        $data['ctf_challenges'][$key]['added_date'] = $v['added_date'];
    }
    if(isset($v['points'])) {
        $data['ctf_challenges'][$key]['points'] = $v['points'];
    }
    if (isset($v['walkthrough'])) {
        $data['ctf_challenges'][$key]['walkthrough'] = $v['walkthrough'];
    }
    if(isset($v['flag'])) {
        $data['ctf_challenges'][$key]['flag'] = $v['flag'];
    }
}

// Malware
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/malware?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['malware'] = [];
foreach ($obj['resource'] as $key => $v) {
    $data['malware'][$key]["_id"] = $v["_id"];
    $data['malware'][$key]["name"] = $v["name"];
    if(isset($v['summary'])) {
        $data['malware'][$key]["summary"] = $v['summary'];
    }
    if(isset($v['platform'])) {
        $data['malware'][$key]["platform"] = $v['platform'];
    }
    if(isset($v['type'])) {
        $data['malware'][$key]["type"] = $v['type'];
    }
    if(isset($v['date_added'])) {
        $data['malware'][$key]["date_added"] = $v['date_added'];
    }
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
    $filename = hash('md5', $_FILES['app_fileToUpload']['name'].date_timestamp_get(date_create()));
    array_push($files, $filename);

    try{
        $r = $s3->putObject([
            'Bucket' => 'pled_files/vulnerable_applications',
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
                $application_to_add->vulnerable_configuration = $json_data['vulnerable_configuration'];
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

        $body = json_encode($resource, true);
        $dfapikey = 'X-DreamFactory-API-Key:'.$ini_array["api_key"];

        $ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications/',
                         CURLOPT_HTTPHEADER => array($dfapikey,
                                                    'Content-Type: application/json'),
                         CURLOPT_POST => 1,
                         CURLOPT_POSTFIELDS => $body,
                         CURLOPT_RETURNTRANSFER => 1
                        );

        curl_setopt_array($ch, $options);
        
        // Send the request
        $response = curl_exec($ch);

        // Check for errors
        if($response === FALSE){
            die(curl_error($ch));
            $data['error'] = 'dferror';
            echo $twig->render('databaseManagementPage.html', $data); // Render html
        }

        // TODO Find do error handling on response code.
        if ($response == '{"error":{"code":404,"context":null,"message":"Table "vuln_applications" does not exist in the database.","status_code":404}}') {
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
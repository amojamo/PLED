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
    if(isset($v['category'])) {
        $data['ctf_challenges'][$key]['category'] = $v['category'];
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
*	Check if variables that needs to be set is set
*	Return error message and mark fields if not
*
**/
if (empty($_POST['challenge_name']) || empty($_FILES['challenge_fileToUpload']['tmp_name'])) {
	$data['err_challenge_msg'] = "Some fields needs to be filled";
	if (empty($_POST['challenge_name'])) {
		$data['err_challenge_name'] = "errborder";
	} else {
        $data['challenge_name'] = $_POST['challenge_name'];
    }

    if (empty($_FILES['challenge_fileToUpload']['tmp_name'])) {
        $data['err_challenge_file'] = "errborder"; 
    } else {
        $data['challenge_fileToUpload'] = $_POST['challenge_fileToUpload'];
    }

    if (!empty($_POST['challenge_summary'])) {
        $data['challenge_summary'] = $_POST['challenge_summary'];
    }

    if (!empty($_POST['challenge_author'])) {
        $data['challenge_author'] = $_POST['challenge_author'];
    }

    if (!empty($_POST['challenge_creation_date'])) {
        $data['challenge_creation_date'] = $_POST['challenge_creation_date'];
    }

    if (!empty($_POST['challenge_port'])) {
        $data['challenge_port'] = $_POST['challenge_port'];
    }

    $data['challenge_type'] = $_POST['challenge_type'];
    $data['challenge_category'] = $_POST['challenge_category'];
    $data['challenge_difficulty'] = $_POST['challenge_difficulty'];

    if (!empty($_POST['challenge_points'])) {
        $data['challenge_points'] = $_POST['challenge_points'];
    }

    if (!empty($_POST['challenge_walkthrough'])) {
        $data['challenge_walkthrough'] = $_POST['challenge_walkthrough'];
    }

    if (!empty($_POST['challenge_flag'])) {
        echo $_POST['challenge_flag'];
        $data['challenge_flag'] = $_POST['challenge_flag'];
    }

    $data['formtype'] = "challengeform";
    echo $twig->render('databaseManagementPage.html', $data); // Render html
}

/**
*
*   If everyhing that needs to be set is set, we can now
*   insert the challenge into swift and mongodb
*
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
    $content = file_get_contents($_FILES['challenge_fileToUpload']['tmp_name']);
    $filename = hash('md5', $_FILES['challenge_fileToUpload']['name'].date_timestamp_get(date_create()));
    array_push($files, $filename);

    try{
        $r = $s3->putObject([
            'Bucket' => 'pled_files/ctf_challenges',
            'Key' => $filename,
            'Body' => $content
        ]);

        $json = '{}';
        $resurce = json_decode($json);
        $resurce->resource = [];
        $challenge_to_add = json_decode($json);
        $challenge_to_add->name = $_POST['challenge_name'];
        if (!empty($_POST['challenge_summary'])) {
            $challenge_to_add->summary = $_POST['challenge_summary'];
        }
        if (!empty($_POST['challenge_author'])) {
            $challenge_to_add->author = $_POST['challenge_author'];
        }
        if (!empty($_POST['challenge_creation_date'])) {
            $challenge_to_add->creation_date = $_POST['challenge_creation_date'];
        }
        if (!empty($_POST['challenge_port'])) {
            $challenge_to_add->port = $_POST['challenge_port'];
        }
        if ($_POST['challenge_type'] != "---") {
            $challenge_to_add->type = $_POST['challenge_type'];
        }
        if ($_POST['challenge_category'] != "---") {
            $challenge_to_add->category = $_POST['challenge_category'];
        }
        if ($_POST['challenge_difficulty'] != "---") {
            $challenge_to_add->difficulty = $_POST['challenge_difficulty'];
        }
        if (!empty($_POST['challenge_points'])) {
            $challenge_to_add->points = $_POST['challenge_points'];
        }
        if (!empty($_POST['challenge_walkthrough'])) {
            $challenge_to_add->walkthrough = $_POST['challenge_walkthrough'];
        }
        if (!empty($_POST['challenge_flag'])) {
            $challenge_to_add->flag = $_POST['challenge_flag'];
        }
        $challenge_to_add->file_path = $filename;

        $resource->resource[0] = $challenge_to_add;

        $body = json_encode($resource, true);

        $ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges/',
                         CURLOPT_HTTPHEADER => array('X-DreamFactory-API-Key: c585d342e289fe06b314e202d4f4bae1405ea43004291da4becbdedbb75e8781',
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
        if ($response == '{"error":{"code":404,"context":null,"message":"Table "ctf_challenges" does not exist in the database.","status_code":404}}') {
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
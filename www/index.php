<?php
require_once "./vendor/autoload.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
//phpinfo();	
$loader = new Twig_Loader_Filesystem('views');
$twig = new Twig_Environment($loader, array());

if(isset($_POST['generateConfig'])) {
	$ip = $_POST['apiurl'];
	$validated = aunthenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $ini_array['ip']);

	if (!$validated){

		header('WWW-Authenticate: Basic realm="PLED"');
		header('HTTP/1.0 401 Unauthorized');
		die('1Unauthorized');
	}
	$file = fopen($_SERVER['DOCUMENT_ROOT']."/conf/phpconfig.ini", 'w');
	$data = 'api_key = '.$_POST['apikey'].PHP_EOL.
			'ip = '.$_POST['apiurl'].PHP_EOL.
			's3_key = '.$_POST['s3key'].PHP_EOL.
			's3_secret = '.$_POST['s3secret'].PHP_EOL.
			's3_region = '.$_POST['s3region'].PHP_EOL.
			's3_endpoint = '.$_POST['s3endpoint'].PHP_EOL;
	fwrite($file, $data);
	fclose($file);
	header("Location: index.php");

	
}

if (file_exists($_SERVER['DOCUMENT_ROOT']."/conf/phpconfig.ini")) {
	$ini_array = parse_ini_file("./conf/phpconfig.ini", true);
} else {
	echo $twig->render('generateConfig.html', array());
	die();
}

//Authenticate in Dreamfactory with username and password
$validated = aunthenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $ini_array['ip']);

if (!$validated){

	header('WWW-Authenticate: Basic realm="PLED"');
	header('HTTP/1.0 401 Unauthorized');
	die('1Unauthorized');
} 
//User arrives here if authenticated

$s3 = include 'src/openstack/openstack.php';

if(isset($_GET['uploaded'])){
	$data['uploaded'] = $_GET['uploaded'];
}
if(isset($_GET['updated'])){
	$data['updated'] = $_GET['updated'];
}
if(isset($_GET['deleted'])) {
	$data['deleted'] = $_GET['deleted'];
}

// Get contents from database '.$ini_array["ip"].'
// Vuln_applications
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['vuln_applications'] = [];
if ($json) {
	foreach ($obj['resource'] as $key => $v) {
		$data['vuln_applications'][$key]["_id"] = $v['_id'];
		$data['vuln_applications'][$key]["application_name"] = $v['application_name'];
		if(isset($v['exploitdb_id'])) {
			$data['vuln_applications'][$key]["exploitdb_id"] = $v['exploitdb_id'];
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
			if(isset($v['exploitdb_id'])) {
				$data['vuln_applications'][$key]["file"] = $v['file_path'];
			} else {
				$cmd = $s3->getCommand('GetObject', [
					'Bucket' => 'pled_files',
					'Key'    => 'vuln_applications/'.$v['file_path']
				]);
				$signed_url = $s3->createPresignedRequest($cmd, '+1 hour');
				$data['vuln_applications'][$key]['file'] = $signed_url->getUri();
			}
		}
		if(isset($v['summary'])) {
			$data['vuln_applications'][$key]["summary"] = $v['summary'];
		}
		if(isset($v['category'])) {
			$data['vuln_applications'][$key]["category"] = $v['category'];
		}
		if(isset($v['tag'])) {
			$data['vuln_applications'][$key]["tag"] = $v['tag'];
		}
	}
}
// ctf_challenges
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['ctf_challenges'] = [];
if ($json) {
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
		if(isset($v['file_path'])) {
			$cmd = $s3->getCommand('GetObject', [
				'Bucket' => 'pled_files',
				'Key'    => 'vuln_applications/'.$v['file_path']
			]);
			$signed_url = $s3->createPresignedRequest($cmd, '+1 hour');
			$data['ctf_challenges'][$key]['file'] = $signed_url->getUri();
		}
	}
}
// Malware
$json = file_get_contents('http://'.$ini_array["ip"].'/api/v2/mongodb/_table/malware?limit=4&order=_id%20DESC&api_key='.$ini_array["api_key"]);
$obj = json_decode($json, true);
$data['malware'] = [];
if ($json) {
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
		if(isset($v['file_path'])) {
			$cmd = $s3->getCommand('GetObject', [
				'Bucket' => 'pled_files',
				'Key'    => 'vuln_applications/'.$v['file_path']
			]);
			$signed_url = $s3->createPresignedRequest($cmd, '+1 hour');
			$data['malware'][$key]['file'] = $signed_url->getUri();
		}
	}
}


echo $twig->render('databaseManagementPage.html', $data);

function aunthenticate($username, $password, $ip) {
	$username = urlencode($username);
	$ch = curl_init();
	$options = array(CURLOPT_URL => 'http://'.$username.':'.$password.'@'.$ip.'/api/v2/mongodb/', 
		CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
		CURLOPT_CUSTOMREQUEST => 'GET',
		CURLOPT_RETURNTRANSFER => true
		);
	
	curl_setopt_array($ch, $options);
	// Send the request
	$response = curl_exec($ch);
	$obj = json_decode($response, true);
    // Check for errors
	if (isset($obj['error'])) {
		return false;
	} else {
		return true;
	}


}
?>
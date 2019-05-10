<?php
require_once "../vendor/autoload.php";

//phpinfo();
$loader = new Twig_Loader_Filesystem('../views');
$twig = new Twig_Environment($loader, array());
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
	if(isset($v['added_date'])) {
		$data['malware'][$key]["added_date"] = $v['added_date'];
	}
}

if($_POST['app_cve'] == ""){
	$data['errcve'] = "errborder";
	$data["placeholdercve"] = "Please fill out this field for autofill to work";
	echo $twig->render('databaseManagementPage.html', $data);
} else {
	/* Remember other set fields */
	if(!empty($_POST['app_name'])){
		$data['app_name'] = $_POST['app_name'];
	}
	if(!empty($_POST['app_summary'])){
		$data['app_summary'] = $_POST['app_summary'];
	}
	if(!empty($_POST['app_category'])){
		$data['app_category'] = $_POST['app_category'];
	}
	if(!empty($_POST['app_platform'])){
		$data['app_platform'] = $_POST['app_platform'];
	}
	if(!empty($_POST['app_tag'])){
		$data['app_tag'] = $_POST['app_tag'];
	}

	/* Get CVE-info from circl */
	$cve = $_POST['app_cve'];
	$url = 'http://cve.circl.lu/api/cve/' . $cve;
	$json = file_get_contents($url);

	if($json !='null') {
		$json_data = json_decode($json, true);
		$data['cve'] = $cve;
		$data['cvesummary'] = $json_data['summary'];
		$data['cvss'] = $json_data['cvss'];
		
		echo $twig->render('databaseManagementPage.html', $data);
	} else {
		$data['errcve'] = "errborder";
		$data['placeholdercve'] = "no info on this cve";
		echo $twig->render('databaseManagementPage.html', $data);
	}
}
	

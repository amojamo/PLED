<?php
require_once "../vendor/autoload.php";

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
	if(isset($v['port'])) {
		$data['ctf_challenges'][$key]['port'] = $v['port'];
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
*	If Search input is empty
*
**/
if(empty($_POST['search'])) {

	// Handle empty search res
	$data['placeholdercve'] = "CVE-ID";
	echo $twig->render('databaseManagementPage.html', $data);
} 
/**
*
*	If Search input not empty
*
**/
else {
	if (!empty($_POST['from'])) {
		if($_POST['from'] == "modify") {
			$data['findres'] = [];
			
			// vuln_applications
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(application_name%20like%20%' . $_POST['search'] . '%)%20or%20(exploitdb_id%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)%20or%20(platform%20like%20%' . $_POST['search'] . '%)%20or%20(published_date%20like%20%' . $_POST['search'] . '%)%20or%20(cve%20like%20%' . $_POST['search'] . '%)%20or%20(cve_summary%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['findres'][$key]["Upload_Type"] = "Vulnerable Application";
				$data['findres'][$key]["_id"] = $v['_id'];
				$data['findres'][$key]["application_name"] = $v['application_name'];
				if(isset($v['exploitdb_id'])) {
					$data['findres'][$key]["exploitdb_id"] = $v['exploitdb_id'];
				}
				if(isset($v['type'])) {
					$data['findres'][$key]["type"] = $v['type'];
				}
				if(isset($v['platform'])) {
					$data['findres'][$key]["platform"] = $v['platform'];
				}
				if(isset($v['published_date'])) {
					$data['findres'][$key]["published_date"] = $v['published_date'];
				}
				if(isset($v['added_date'])) {
					$data['findres'][$key]["added_date"] = $v['added_date'];
				}
				$data['findres'][$key]["cve"] = $v['cve'];
				if(isset($v['cve_summary'])) {
					$data['findres'][$key]["cve_summary"] = $v['cve_summary'];
				}
				if(isset($v['cwe'])) {
					$data['findres'][$key]["cwe"] = $v['cwe'];
				}
				if(isset($v['impact'])) {
					$data['findres'][$key]["impact"] = $v['impact'];
				}
				if(isset($v['vulnerable_configuration'])) {
					$data['findres'][$key]["vulnerable_configuration"] = $v['vulnerable_configuration'];
				}
				if(isset($v['file_path'])) {
					$data['findres'][$key]["file_path"] = $v['file_path'];
				}
				if(isset($v['summary'])) {
					$data['findres'][$key]["summary"] = $v['summary'];
				}
				if(isset($v['tag'])) {
					$data['findres'][$key]["tag"] = $v['tag'];
				}
			}
			// ctf_challenges
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(name%20like%20%' . $_POST['search'] . '%)%20or%20(summary%20like%20%' . $_POST['search'] . '%)%20or%20(author%20like%20%' . $_POST['search'] . '%)%20or%20(port%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)%20or%20(category%20like%20%' . $_POST['search'] . '%)%20or%20(difficulty%20like%20%' . $_POST['search'] . '%)%20or%20(points%20like%20%' . $_POST['search'] . '%)%20or%20(walkthrough%20like%20%' . $_POST['search'] . '%)%20or%20(flag%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['findres'][$key]["Upload_Type"] = "CTF Challenge";
				$data['findres'][$key]['_id'] = $v['_id'];
				$data['findres'][$key]['name'] = $v['name'];
				if(isset($v['summary'])){
					$data['findres'][$key]['summary'] = $v['summary'];
				}
				if(isset($v['author'])) {
					$data['findres'][$key]["author"] = $v['author'];
				}
				if(isset($v['creation_date'])) {
					$data['findres'][$key]["creation_date"] = $v['creation_date'];
				}
				if(isset($v['port'])) {
					$data['findres'][$key]['port'] = $v['port'];
				}
				if(isset($v['type'])){
					$data['findres'][$key]['type'] = $v['type'];
				}
				if(isset($v['category'])) {
					$data['findres'][$key]['category'] = $v['category'];
				}
				if(isset($v['difficulty'])) {
					$data['findres'][$key]['difficulty'] = $v['difficulty'];
				}
				if(isset($v['added_date'])) {
					$data['findres'][$key]['added_date'] = $v['added_date'];
				}
				if(isset($v['points'])) {
					$data['findres'][$key]['points'] = $v['points'];
				}
				if (isset($v['walkthrough'])) {
					$data['findres'][$key]['walkthrough'] = $v['walkthrough'];
				}
				if(isset($v['flag'])) {
					$data['findres'][$key]['flag'] = $v['flag'];
				}
			}
			// malware
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/malware?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(name%20like%20%' . $_POST['search'] . '%)%20or%20(summary%20like%20%' . $_POST['search'] . '%)%20or%20(platform%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['findres'][$key]["Upload_Type"] = "Malware";
				$data['findres'][$key]["_id"] = $v['_id'];
				$data['findres'][$key]["name"] = $v['name'];
				if(isset($v['summary'])) {
					$data['findres'][$key]['summary'] = $v['summary'];
				}
				if(isset($v['platform'])) {
					$data['findres'][$key]['platform'] = $v['platform'];
				}
				if(isset($v['type'])) {
					$data['findres'][$key]['type'] = $v['type'];
				}
				if(isset($v['date_added'])) {
					$data['findres']['key']['date_added'] = $v['date_added'];
				}
			}

			$data['findquery'] = $_POST['search'];
			$data['placeholdercve'] = "CVE-ID";
			echo $twig->render('databaseManagementPage.html', $data);
		} 


		if ($_POST['from'] == "search") {
			$data['searchres'] = [];

			// vuln_applications
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(application_name%20like%20%' . $_POST['search'] . '%)%20or%20(exploitdb_id%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)%20or%20(platform%20like%20%' . $_POST['search'] . '%)%20or%20(published_date%20like%20%' . $_POST['search'] . '%)%20or%20(cve%20like%20%' . $_POST['search'] . '%)%20or%20(cve_summary%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['searchres'][$key]["Upload_Type"] = "Vulnerable Application";
				$data['searchres'][$key]["_id"] = $v['_id'];
				$data['searchres'][$key]["application_name"] = $v['application_name'];
				if(isset($v['exploitdb_id'])) {
					$data['searchres'][$key]["exploitdb_id"] = $v['exploitdb_id'];
				}
				if(isset($v['type'])) {
					$data['searchres'][$key]["type"] = $v['type'];
				}
				if(isset($v['platform'])) {
					$data['searchres'][$key]["platform"] = $v['platform'];
				}
				if(isset($v['published_date'])) {
					$data['searchres'][$key]["published_date"] = $v['published_date'];
				}
				if(isset($v['added_date'])) {
					$data['searchres'][$key]["added_date"] = $v['added_date'];
				}
				$data['searchres'][$key]["cve"] = $v['cve'];
				if(isset($v['cve_summary'])) {
					$data['searchres'][$key]["cve_summary"] = $v['cve_summary'];
				}
				if(isset($v['cwe'])) {
					$data['searchres'][$key]["cwe"] = $v['cwe'];
				}
				if(isset($v['impact'])) {
					$data['searchres'][$key]["impact"] = $v['impact'];
				}
				if(isset($v['vulnerable_configuration'])) {
					$data['searchres'][$key]["vulnerable_configuration"] = $v['vulnerable_configuration'];
				}
				if(isset($v['file_path'])) {
					$data['searchres'][$key]["file_path"] = $v['file_path'];
				}
				if(isset($v['summary'])) {
					$data['searchres'][$key]["summary"] = $v['summary'];
				}
				if(isset($v['tag'])) {
					$data['searchres'][$key]["tag"] = $v['tag'];
				}
			}

			// ctf_challenges
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(name%20like%20%' . $_POST['search'] . '%)%20or%20(summary%20like%20%' . $_POST['search'] . '%)%20or%20(author%20like%20%' . $_POST['search'] . '%)%20or%20(port%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)%20or%20(category%20like%20%' . $_POST['search'] . '%)%20or%20(difficulty%20like%20%' . $_POST['search'] . '%)%20or%20(points%20like%20%' . $_POST['search'] . '%)%20or%20(walkthrough%20like%20%' . $_POST['search'] . '%)%20or%20(flag%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['searchres'][$key]["Upload_Type"] = "CTF Challenge";
				$data['searchres'][$key]['_id'] = $v['_id'];
				$data['searchres'][$key]['name'] = $v['name'];
				if(isset($v['summary'])){
					$data['searchres'][$key]['summary'] = $v['summary'];
				}
				if(isset($v['author'])) {
					$data['searchres'][$key]["author"] = $v['author'];
				}
				if(isset($v['creation_date'])) {
					$data['searchres'][$key]["creation_date"] = $v['creation_date'];
				}
				if(isset($v['port'])) {
					$data['searchres'][$key]['port'] = $v['port'];
				}
				if(isset($v['type'])){
					$data['searchres'][$key]['type'] = $v['type'];
				}
				if(isset($v['category'])) {
					$data['searchres'][$key]['category'] = $v['category'];
				}
				if(isset($v['difficulty'])) {
					$data['searchres'][$key]['difficulty'] = $v['difficulty'];
				}
				if(isset($v['added_date'])) {
					$data['searchres'][$key]['added_date'] = $v['added_date'];
				}
				if(isset($v['points'])) {
					$data['searchres'][$key]['points'] = $v['points'];
				}
				if (isset($v['walkthrough'])) {
					$data['searchres'][$key]['walkthrough'] = $v['walkthrough'];
				}
				if(isset($v['flag'])) {
					$data['searchres'][$key]['flag'] = $v['flag'];
				}
			}

			// malware
			$url = 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/malware?filter=(_id%20like%20%' . $_POST['search'] . '%)%20or%20(name%20like%20%' . $_POST['search'] . '%)%20or%20(summary%20like%20%' . $_POST['search'] . '%)%20or%20(platform%20like%20%' . $_POST['search'] . '%)%20or%20(type%20like%20%' . $_POST['search'] . '%)&order=_id%20DESC&api_key='.$ini_array["api_key"];
			$json = file_get_contents($url);
			$obj = json_decode($json, true);
			foreach ($obj['resource'] as $key => $v) {
				$data['searchres'][$key]["Upload_Type"] = "Malware";
				$data['searchres'][$key]["_id"] = $v['_id'];
				$data['searchres'][$key]["name"] = $v['name'];
				if(isset($v['summary'])) {
					$data['searchres'][$key]['summary'] = $v['summary'];
				}
				if(isset($v['platform'])) {
					$data['searchres'][$key]['platform'] = $v['platform'];
				}
				if(isset($v['type'])) {
					$data['searchres'][$key]['type'] = $v['type'];
				}
				if(isset($v['date_added'])) {
					$data['searchres']['key']['date_added'] = $v['date_added'];
				}
			}

			$data['query'] = $_POST['search'];
			$data['placeholdercve'] = "CVE-ID";
			echo $twig->render('databaseManagementPage.html', $data);
			
		}
	}
}

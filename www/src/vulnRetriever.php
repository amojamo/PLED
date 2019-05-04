<?php
require_once "../vendor/autoload.php";
ob_end_flush();
//phpinfo();
$loader = new Twig_Loader_Filesystem('../views');
$twig = new Twig_Environment($loader, array());
//url for raw csv data from exploitdb
$exploitUrl = 'https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv';
#get csv file and parse ids
$csvFromUrl = file_get_contents($exploitUrl);
$csvData = array_map('str_getcsv', file($exploitUrl));
//Remove first element since its the csv column names
array_shift($csvData);
$vulnData = [];



//testOne($csvData);
testFull($csvData);


function testOne($csvData) {
	$id = $csvData[1][0];
	//cached version of site, since exploitdb blocked me (google also blocked me)
	$url = "https://www.exploit-db.com/exploits/$id";
	echo 'Loading in ' . $url . '....';
	flush();
	$doc = new DOMDocument();
	libxml_use_internal_errors(true);
	sleep(1);
	$resp = curl($url);
	if ($resp['error'] == 0 && strpos($resp['html'], "/apps/")) {
		$vulnData['id'] = $id;
		$vulnData['descr'] = $csvData[1][2];
		$vulnData['date'] = $csvData[1][3];
		$vulnData['type'] = $csvData[1][5];
		$vulnData['platform'] = $csvData[1][6];
		$doc->loadHTML($resp['html']);
		//Find both CVE and download url with 'a' tag
		$atags = $doc->getElementsByTagName('a');
		foreach ($atags as $atag) {
			$link = $atag->getAttribute('href');
			if (strpos($link, 'apps')) {
				$vulnData['appUrl'] = 'https://www.exploit-db.com' . $link;
			} elseif (strpos($link, 'CVE')) {
				$vulnData['cve'] = 'CVE-' . trim($atag->nodeValue);
			}
		}
	} else {
		echo 'no app';
		echo 'Exited with error: ' . $resp['error'];

	}
	echo '<pre>';
	print_r($vulnData);
}


function testFull ($csvData) {
	echo 'This is a test for scraping exploitdb for vulnerable apps <br> it may take a while and will create a bit of network traffic, if you want to cancel you have 10 seconds<br>';
	flush();
	sleep(15);
	foreach ($csvData as $exploit) {
		//For testing purposes, 
		//does not store the retrieved data, just displays
		$vulnData = [];
		//The first element is always id
		$id = $exploit[0];
		$url = "https://www.exploit-db.com/exploits/$id";
		//flush since output buffering is disabled to see when the
		//data is done loading
		echo 'Loading in ' . $url . '....';
		flush();
		//start new DOMdocument to load site html
		$doc = new DOMDocument();
		libxml_use_internal_errors(true);
		//Sleep 1 second each time to not overwhelm the site
		sleep(1);
		$resp = curl($url);
		//curl returns an error code if something went wrong
		if ($resp['error'] == 0) {
			//Check if the loaded vuln has an app reference
			if (strpos($resp['html'], "/apps/")) {
				//if so load in and get the data
				$doc->loadHTML($resp['html']);
				$vulnData['id'] = $id;
				$vulnData['descr'] = $exploit[2];
				$vulnData['date'] = $exploit[3];
				$vulnData['type'] = $exploit[5];
				$vulnData['platform'] = $exploit[6];
				
				//Find both CVE and download url with 'a' tag
				$atags = $doc->getElementsByTagName('a');
				foreach ($atags as $atag) {
					//get the href and see if its the app link
					$link = $atag->getAttribute('href');
					if (strpos($link, 'apps')) {
						$vulnData['appUrl'] = 'https://www.exploit-db.com' . $link;
					//also get CVE if possible
					} elseif (strpos($link, 'CVE')) {
						$vulnData['cve'] = 'CVE-' . trim($atag->nodeValue);
					}
				}
				//Print out the data and move on
				//can also be stored somewhere here
				echo '<pre>';
				print_r($vulnData);
				flush();
			} else {
				//if the html has no /apps/
				echo 'No app<br>';
			}
		} else {
			//if curl returns an error code
			echo 'Exited with error: ' . $resp['error'];
			flush();
			break;

		}
	}

}
#https://www.exploit-db.com/search?id=<ID>&verified=true&hasapp=true
##if true then get CVE from page and get app url -> store in list or array
## show all exploitdb vulns that has app


function curl($url, $cookie = false, $post = false, $header = false, $follow_location = false, $referer=false,$proxy=false)
{
        $userAgent = 'Googlebot/2.1 (http://www.googlebot.com/bot.html)';
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_USERAGENT, $userAgent);
        curl_setopt($curl, CURLOPT_AUTOREFERER, true);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1 );
        curl_setopt($curl, CURLOPT_TIMEOUT, 2 );
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 10);  
        $curlData['html'] = curl_exec( $curl );
        $curlData['error'] = curl_errno($curl);
	    curl_close( $curl);
    return $curlData;
}

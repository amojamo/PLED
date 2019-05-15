<?php
require_once "../vendor/autoload.php";
require_once "../src/classes/Api.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
// Set up Twig loader system
$loader = new Twig_Loader_Filesystem('../views');
$twig   = new Twig_Environment($loader, array());
$ini_array = parse_ini_file("../conf/phpconfig.ini", true);
$s3 = include 'openstack/openstack.php';

//Initiate API class
$api = new Api($ini_array);
//Get collections from config
$collections = explode(',', $ini_array['collections']);

//Get all data from collection
foreach($collections as $collection){
	$data[$collection] = $api->getContents($collection);
}
/**
*
*	If Search input is empty, handle the empty response,
*	else create a search and return response in $data['findres']
*	and $data['searchres'] depending on if the search is sent from
*	the 'find'- or 'modify'-tab.
*
**/
if(empty($_POST['search'])) {
	/*
	*	Place handling for empty seach here
	*/
	$data['placeholdercve'] = "CVE-ID";
	echo $twig->render('databaseManagementPage.html', $data);
} else {
	if (!empty($_POST['from'])) {
		$search = $_POST['search'];
		$search = urlencode($search);
		// If the search is from the 'Modify' tab
		if($_POST['from'] == "modify") {
			$data['findres'] = [];
			foreach($collections as $collection){
				$data['findres'][$collection] = $api->search($search, $collection);
			}

			$data['findquery'] = $_POST['search'];
			$data['placeholdercve'] = "CVE-ID";
			echo $twig->render('databaseManagementPage.html', $data);
		} 
		// If the search is from the 'Find' tab
		if ($_POST['from'] == "search") {
			$data['searchres'] = [];
			foreach($collections as $collection){
				$data['searchres'][$collection] = $api->search($search, $collection);
			}

			$data['query'] = $_POST['search'];
			$data['placeholdercve'] = "CVE-ID";
			echo $twig->render('databaseManagementPage.html', $data);
			
		}
	}
}

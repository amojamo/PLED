<?php
session_start();
require_once "./vendor/autoload.php";
require_once "./src/classes/Api.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
//phpinfo();	
$loader = new Twig_Loader_Filesystem('views');
$twig = new Twig_Environment($loader, array());

/**
*
*   If its the first time starting the webpage, the phpconfig.ini is not present
*   user will be prompted to enter some data to create the config
*
**/
if(isset($_POST['generateConfig'])) {
	$ip = $_POST['apiurl'];
	//Authenticate function, checks with the api to see if the user is allowed access
	$validated = aunthenticate($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $ini_array['ip']);
	//If not validated then show username / password prompt
	if (!$validated){

		header('WWW-Authenticate: Basic realm="PLED"');
		header('HTTP/1.0 401 Unauthorized');
		die('1Unauthorized');
	}
	//If validated, create the config file
	$file = fopen($_SERVER['DOCUMENT_ROOT']."/conf/phpconfig.ini", 'w');
	$data = 'api_key = '.$_POST['apikey'].PHP_EOL.
			'ip = '.$_POST['apiurl'].PHP_EOL.
			's3_key = '.$_POST['s3key'].PHP_EOL.
			's3_secret = '.$_POST['s3secret'].PHP_EOL.
			's3_region = '.$_POST['s3region'].PHP_EOL.
			's3_endpoint = '.$_POST['s3endpoint'].PHP_EOL.
			'collections = vuln_applications,ctf_challenges,malware'.PHP_EOL;
	fwrite($file, $data);
	fclose($file);
	//Redirect to the index
	header("Location: index.php");

	
}

//Check if config file is set, if not prompt user to create it
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
//Create Api object, parameter is the php config created during first time setup
$api = new Api($ini_array);
//Collections are separated by commas
$collections = explode(',', $ini_array['collections']);
//Create collections
$api->createCollections($collections);

//For each collection, get data and render with Twig
foreach($collections as $collection){
	$data[$collection] = $api->getContents($collection);
}
echo $twig->render('databaseManagementPage.html', $data);


/**
*	Authenticate user with the API
*
*	@param $username - username to check
*	@param $password - password accosiated with the username
*   @return $ip - ip address of the dreamfactory host 
*
**/
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
    // Check for errors, error occurs of the user was denied access
	if (isset($obj['error'])) {
		return false;
	} else {
		return true;
	}


}
?>
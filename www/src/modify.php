<?php
require_once "../vendor/autoload.php";
use Aws\S3\S3Client;
use Aws\Exception\AwsException;

// Set up Twig loader system
$loader = new Twig_Loader_Filesystem('../views');
$twig   = new Twig_Environment($loader, array());
$ini_array = parse_ini_file("../conf/phpconfig.ini", true);

/**
*
*	Find out what type of content is being updated
*	Find out if any of the fields are changed
*	If they are changed, add them to request body
*	Send the request and return to index.php with message
*
*	TODO: DreamFactory Rest API has no way of unseting empty keys/value
*	pairs. This means the flexibility of a document db is lost.
*	Posted on their forums, if they have an equivalent, if not,
*	this method may need to be conected directly to mongodb.
*	The feature is neccesary if users unsets a mandatory to have value,
*	such as "name".
**/
if($_POST['upload_type'] == "vuln_application") {
	$resource = json_decode('{}');
	$resource->resource = [];
	$application_to_modify = json_decode('{}');
	if (!empty($_POST['app_name'])) 
		$application_to_modify->application_name = $_POST['app_name'];
	//if (!empty($_POST['app_summary'])) 
		$application_to_modify->summary = $_POST['app_summary'];
	//if (!empty($_POST['app_cve'])) 
		$application_to_modify->cve = $_POST['app_cve'];
	//if ($_POST['app_platform'] != "any")
		$application_to_modify->platform = $_POST['app_platform'];
	//if ($_POST['app_tag'] != "none") 
		$application_to_modify->tag = $_POST['app_tag'];

	$resource->resource[0] = $application_to_modify;
	$body = json_encode($resource, true);
	sendPatchRequest('vuln_applications', $body, $ini_array);

} else if ($_POST['upload_type'] == "ctf_challenge") {	
	$resource = json_decode('{}');
	$resource->resource = [];
	$challenge_to_modify = json_decode('{}');
	if(!empty($_POST['challenge_name']))
		$challenge_to_modify->name = $_POST['challenge_name'];
	//if(!empty($_POST['challenge_author']))
		$challenge_to_modify->author = $_POST['challenge_author'];
	//if(!empty($_POST['challenge_port']))
		$challenge_to_modify->port = $_POST['challenge_port'];
	//if($_POST['challenge_type'] != "other")
		$challenge_to_modify->type = $_POST['challenge_type'];
	//($_POST['challenge_category'] != "other")
		$challenge_to_modify->category = $_POST['challenge_category'];
	//if($_POST['challenge_difficulty'] != "other")
		$challenge_to_modify->difficulty = $_POST['challenge_difficulty'];
	//if(!empty($_POST['challenge_points']))
		$challenge_to_modify->points = $_POST['challenge_points'];
	//if(!empty($_POST['challenge_walkthrough']))
		$challenge_to_modify->walkthrough = $_POST['challenge_walkthrough'];
	//if(!empty($_POST['challenge_flag']))
		$challenge_to_modify->flag = $_POST['challenge_flag'];
	
	$resource->resource[0] = $challenge_to_modify;
	$body = json_encode($resource, true);
	sendPatchRequest('ctf_challenges', $body, $ini_array);

} else if ($_POST['upload_type'] == "malware") {
	$resource = json_decode('{}');
	$resource->resource = [];
	$malware_to_modify = json_decode('{}');
	if(!empty($_POST['malware_name']))
		$malware_to_modify->name = $_POST['malware_name'];
	$malware_to_modify->summary = $_POST['malware_summary'];
	$malware_to_modify->platform = $_POST['malware_platform'];
	$malware_to_modify->type = $_POST['malware_type'];

	$resource->resource[0] = $malware_to_modify;
	$body = json_encode($resource, true);
	sendPatchRequest('malware', $body, $ini_array);

} else {
	// This should not happen
}

function sendPatchRequest($collection, $body, $ini_array) {
	$dfapikey = 'X-DreamFactory-API-Key:'.$ini_array["api_key"];

		$ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'?filter=_id='.$_POST['_id'],
                         CURLOPT_HTTPHEADER => array($dfapikey,
                                                    'Content-Type: application/json'),
                         CURLOPT_CUSTOMREQUEST => 'PATCH',
                         CURLOPT_POSTFIELDS => $body,
                         CURLOPT_RETURNTRANSFER => 1
                        );

        curl_setopt_array($ch, $options);

        // Send the request
        $response = curl_exec($ch);
        $obj = json_decode($response, true);
        
        // Check for errors
        if($response === FALSE){
            die(curl_error($ch));
            $data['response'] = 'Something is wrong, check DreamFactory configurations';
            echo $twig->render('databaseManagementPage.html', $data); // Render html
        }

        // TODO Find do error handling on response code.
        if (!empty($obj['error']['code']) && ($obj['error']['code'] != 200)) {
            $data['updated'] = 'false';
        } else {
            $data['updated'] = 'true';
        } 
        header('Location: ../index.php?updated=' . $data['updated']);
}
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
// Go through the collections and check that they are in the database
foreach($collections as $collection){   
	$data[$collection] = $api->getContents($collection);   
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
    if (!empty($_POST['challenge_summary'])) 
        $data['challenge_summary'] = $_POST['challenge_summary'];
    if (!empty($_POST['challenge_author'])) 
        $data['challenge_author'] = $_POST['challenge_author'];
    if (!empty($_POST['challenge_creation_date'])) 
        $data['challenge_creation_date'] = $_POST['challenge_creation_date'];
    if (!empty($_POST['challenge_port'])) 
        $data['challenge_port'] = $_POST['challenge_port'];
    $data['challenge_type'] = $_POST['challenge_type'];
    $data['challenge_category'] = $_POST['challenge_category'];
    $data['challenge_difficulty'] = $_POST['challenge_difficulty'];
    if (!empty($_POST['challenge_points'])) 
        $data['challenge_points'] = $_POST['challenge_points'];
    if (!empty($_POST['challenge_walkthrough'])) 
        $data['challenge_walkthrough'] = $_POST['challenge_walkthrough'];
    if (!empty($_POST['challenge_flag'])) 
        $data['challenge_flag'] = $_POST['challenge_flag'];
    $data['formtype'] = "challengeform";
    echo $twig->render('databaseManagementPage.html', $data); // Render html
}

/**
*
*   If everyhing that needs to be set is set, we can now
*   insert the challenge into swift and mongodb
*
*   Stores:
*     ctf challenge data:
*       - name
*       - summary
*       - author
*       - creation date
*       - port
*       - type
*       - category
*       - difficulty
*       - points
*       - walkthrough
*       - flag
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
    //$filename = hash('md5', $_FILES['challenge_fileToUpload']['name'].date_timestamp_get(date_create()));
    $filename = uniqid().'_'.$_FILES['challenge_fileToUpload']['name'];
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
        if (!empty($_POST['challenge_summary'])) 
            $challenge_to_add->summary = $_POST['challenge_summary'];
        if (!empty($_POST['challenge_author'])) 
            $challenge_to_add->author = $_POST['challenge_author'];
        if (!empty($_POST['challenge_creation_date'])) 
            $challenge_to_add->creation_date = $_POST['challenge_creation_date'];
        if (!empty($_POST['challenge_port'])) 
            $challenge_to_add->port = $_POST['challenge_port'];
        if ($_POST['challenge_type'] != "---") 
            $challenge_to_add->type = $_POST['challenge_type'];
        if ($_POST['challenge_category'] != "---") 
            $challenge_to_add->category = $_POST['challenge_category'];
        if ($_POST['challenge_difficulty'] != "---") 
            $challenge_to_add->difficulty = $_POST['challenge_difficulty'];
        if (!empty($_POST['challenge_points'])) 
            $challenge_to_add->points = $_POST['challenge_points'];
        if (!empty($_POST['challenge_walkthrough'])) 
            $challenge_to_add->walkthrough = $_POST['challenge_walkthrough'];
        if (!empty($_POST['challenge_flag'])) 
            $challenge_to_add->flag = $_POST['challenge_flag'];
        $challenge_to_add->file_path = $filename;

        $resource->resource[0] = $challenge_to_add;


        $api = new Api($ini_array);
        $body = json_encode($resource, true);
        $res = $api->insert($body, 'ctf_challenges');   // call insert function in Api class
        $obj = json_decode($res['response'], true);
        
        if($res['response'] === FALSE){
            die($res['error']);
            $data['error'] = 'dferror';
            echo $twig->render('databaseManagementPage.html', $data); // Render html
        }

        // Error handling for code != 200
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
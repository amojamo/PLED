<?php
use Aws\S3\S3Client;
use Aws\Exception\AwsException;
class Api {
    private $ini_array;
    private $s3;
    public function __construct($ini_array){
        $this->ini_array = $ini_array;
        $this->s3 = include $_SERVER['DOCUMENT_ROOT'].'/src/openstack/openstack.php';
    }

    private function collectionExists($collection) {    
            $headers = get_headers('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'?limit=4&order=_id%20DESC&api_key='.$this->ini_array["api_key"]);
            return stripos($headers[0], "200 OK")?true:false;
    }
    private function getVuln_applications($json) {
        $data = [];
        $obj = json_decode($json, true);
        foreach ($obj['resource'] as $key => $v) {
            $data[$key]["_id"] = $v['_id'];
            $data[$key]["application_name"] = $v['application_name'];
            if(isset($v['exploitdb_id'])) {
                $data[$key]["exploitdb_id"] = $v['exploitdb_id'];
            }
            if(isset($v['platform'])) {
                $data[$key]["platform"] = $v['platform'];
            }
            if(isset($v['published_date'])) {
                $data[$key]["published_date"] = $v['published_date'];
            }
            if(isset($v['added_date'])) {
                $data[$key]["added_date"] = $v['added_date'];
            }
            $data[$key]["cve"] = $v['cve'];
            if(isset($v['cve_summary'])) {
                $data[$key]["cve_summary"] = $v['cve_summary'];
            }
            if(isset($v['cwe'])) {
                $data[$key]["cwe"] = $v['cwe'];
            }
            if(isset($v['impact'])) {
                $data[$key]["impact"] = $v['impact'];
            }
            if(isset($v['vulnerable_configuration'])) {
                $data[$key]["vulnerable_configuration"] = $v['vulnerable_configuration'];
            }
            if(isset($v['file_path'])) {
                if(isset($v['exploitdb_id'])) {
                    $data[$key]["file"] = $v['file_path'];
                } else {
                    $cmd = $this->s3->getCommand('GetObject', [
                        'Bucket' => 'pled_files',
                        'Key'    => 'vuln_applications/'.$v['file_path']
                    ]);
                    $signed_url = $this->s3->createPresignedRequest($cmd, '+1 hour');
                    $data[$key]['file'] = $signed_url->getUri();
                }
            }
            if(isset($v['summary'])) {
                $data[$key]["summary"] = $v['summary'];
            }
            if(isset($v['category'])) {
                $data[$key]["category"] = $v['category'];
            }
            if(isset($v['tag'])) {
                $data[$key]["tag"] = $v['tag'];
            }
        }
        return $data;
    }
    private function getCtf_challenges($json) {
        $data = [];
        $obj = json_decode($json, true);
        foreach ($obj['resource'] as $key => $v) {
            $data[$key]["_id"] = $v['_id'];
            $data[$key]["name"] = $v['name'];
            if(isset($v['summary'])) {
                $data[$key]["summary"] = $v['summary'];
            }
            if(isset($v['author'])) {
                $data[$key]["author"] = $v['author'];
            }
            if(isset($v['creation_date'])) {
                $data[$key]["creation_date"] = $v['creation_date'];
            }
            if(isset($v['port'])) {
                $data[$key]['port'] = $v['port'];
            }
            if(isset($v['type'])){
                $data[$key]['type'] = $v['type'];
            }
            if(isset($v['category'])) {
                $data[$key]['category'] = $v['category'];
            }
            if(isset($v['difficulty'])) {
                $data[$key]['difficulty'] = $v['difficulty'];
            }
            if(isset($v['added_date'])) {
                $data[$key]['added_date'] = $v['added_date'];
            }
            if(isset($v['points'])) {
                $data[$key]['points'] = $v['points'];
            }
            if (isset($v['walkthrough'])) {
                $data[$key]['walkthrough'] = $v['walkthrough'];
            }
            if(isset($v['flag'])) {
                $data[$key]['flag'] = $v['flag'];
            }
        }
        return $data;
    }
    private function getMalware($json) {
        $data = [];
        $obj = json_decode($json, true);
        foreach ($obj['resource'] as $key => $v) {
            $data[$key]["_id"] = $v["_id"];
            $data[$key]["name"] = $v["name"];
            if(isset($v['summary'])) {
                $data[$key]["summary"] = $v['summary'];
            }
            if(isset($v['platform'])) {
                $data[$key]["platform"] = $v['platform'];
            }
            if(isset($v['type'])) {
                $data[$key]["type"] = $v['type'];
            }
            if(isset($v['added_date'])) {
                $data[$key]["added_date"] = $v['added_date'];
            }
        }
        return $data;
    }
    public function createCollections($collections) {
        //curl -X POST "https://10.212.138.13/api/v2/mongodb/_schema"{\"resource\":[{\"name\":\"test\"}]}"
        foreach($collections as $collection) {        
            if(!$this->collectionExists($collection)){
                echo $collection; 
                $ch = curl_init();
                $json = '{}';
                $resource = json_decode($json);
                $resource->resource = [];
                $col = json_decode($json);
                $col->name = $collection;
                $resource->resource[0] = $col;
                $data = json_encode($resource, true);
                $options = array(CURLOPT_URL => 'http://'.$this->ini_array["ip"].'/api/v2/mongodb/_schema',
                                CURLOPT_HTTPHEADER => array('X-DreamFactory-API-Key:'.$this->ini_array["api_key"],
                                'Content-Type: application/json'),
                                CURLOPT_POST => 1,
                                CURLOPT_POSTFIELDS => $data,
                                CURLOPT_RETURNTRANSFER => 1
                                );

                curl_setopt_array($ch, $options);
                // Send the request
                curl_exec($ch);
            }
        }
    }
    public function getContents($collection) {
        $data = [];
        if($this->collectionExists($collection)){
            $json = file_get_contents('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'?limit=4&order=_id%20DESC&api_key='.$this->ini_array["api_key"]);
            switch ($collection) {
                case 'vuln_applications':
                    $data = $this->getVuln_applications($json);
                    break;
                case 'ctf_challenges':
                    $data = $this->getCtf_challenges($json);
                    break;
                case 'malware':
                    $data = $this->getMalware($json);
                    break;
                default:
                    
            }
        }
        return $data;
        
    }

    public function search($search, $collection) {
        $data = [];
        if($this->collectionExists($collection)){
            switch ($collection) {
                case 'vuln_applications':
                    $json = file_get_contents('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/vuln_applications?filter=(_id%20like%20%' . $search . '%)%20or%20(application_name%20like%20%' . $search . '%)%20or%20(exploitdb_id%20like%20%' . $search . '%)%20or%20(type%20like%20%' . $search . '%)%20or%20(platform%20like%20%' . $search . '%)%20or%20(published_date%20like%20%' . $search . '%)%20or%20(cve%20like%20%' . $search . '%)%20or%20(cve_summary%20like%20%' . $search . '%)&order=_id%20DESC&api_key='.$this->ini_array["api_key"]);
                    $data = $this->getVuln_applications($json);
                    break;
                case 'ctf_challenges':
                    $json = file_get_contents('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/ctf_challenges?filter=(_id%20like%20%' . $search . '%)%20or%20(name%20like%20%' . $search . '%)%20or%20(summary%20like%20%' . $search . '%)%20or%20(author%20like%20%' . $search . '%)%20or%20(port%20like%20%' . $search . '%)%20or%20(type%20like%20%' . $search . '%)%20or%20(category%20like%20%' . $search . '%)%20or%20(difficulty%20like%20%' . $search . '%)%20or%20(points%20like%20%' . $search . '%)%20or%20(walkthrough%20like%20%' . $search . '%)%20or%20(flag%20like%20%' . $search . '%)&order=_id%20DESC&api_key='.$this->ini_array["api_key"]);
                    $data = $this->getCtf_challenges($json);
                    break;
                case 'malware':
                    $json = file_get_contents('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/malware?filter=(_id%20like%20%' . $search . '%)%20or%20(name%20like%20%' . $search . '%)%20or%20(summary%20like%20%' . $search . '%)%20or%20(platform%20like%20%' . $search . '%)%20or%20(type%20like%20%' . $search . '%)&order=_id%20DESC&api_key='.$this->ini_array["api_key"]);
                    $data = $this->getMalware($json);
                    break;
                default:
                    
            }
        }
        return $data;
    }

    public function insert($data, $collection) {
        $ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'/',
                         CURLOPT_HTTPHEADER => array('X-DreamFactory-API-Key:'.$this->ini_array["api_key"],
                                                    'Content-Type: application/json'),
                         CURLOPT_POST => 1,
                         CURLOPT_POSTFIELDS => $data,
                         CURLOPT_RETURNTRANSFER => 1
                        );

        curl_setopt_array($ch, $options);
        
        // Send the request
        $response = curl_exec($ch);
        $res['response'] = $response;
        if($response === FALSE) {
            $res['error'] = curl_error($ch); 
        }
        return $res;
    }

    public function patch($data, $colletion) {
		$ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'?filter=_id='.$_POST['_id'],
                         CURLOPT_HTTPHEADER => array('X-DreamFactory-API-Key:'.$this->ini_array["api_key"],
                                                    'Content-Type: application/json'),
                         CURLOPT_CUSTOMREQUEST => 'PATCH',
                         CURLOPT_POSTFIELDS => $data,
                         CURLOPT_RETURNTRANSFER => 1
                        );

        curl_setopt_array($ch, $options);
        // Send the request
        $response = curl_exec($ch);
        $res['response'] = $response;
        if($response === FALSE) {
            $res['error'] = curl_error($ch); 
        }
        return $res;
    }

    public function delete($id, $collection) {
        $json = file_get_contents('http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'/'.$id.'?fields=file_path&api_key='.$this->ini_array["api_key"]);
        $file_path = json_decode($json, true);

        $ch = curl_init();
        $options = array(CURLOPT_URL => 'http://'.$this->ini_array["ip"].'/api/v2/mongodb/_table/'.$collection.'/'.$id, 
            CURLOPT_HTTPHEADER => array('X-DreamFactory-API-Key:'.$this->ini_array["api_key"], 'Content-Type: application/json'),
            CURLOPT_CUSTOMREQUEST => 'DELETE'
            );

            curl_setopt_array($ch, $options);
            print_r($options);
            // Send the request
            $response = curl_exec($ch);
            $res['response'] = $response;
            $res['file_path'] = $file_path['file_path'];
            if($response === FALSE) {
                $res['error'] = curl_error($ch); 
            }
            return $res;
    }

}



?>
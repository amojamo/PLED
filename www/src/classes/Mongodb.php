<?php
/**
*
*	MongoDB Initilizer
*
**/

class Mongo_DB {
	private $client = "mongodb://root:poot@10.212.137.65";
	private $m;
	private $db;
	private $collection;

	function __construct() {
		$this->m = new MongoDB\Client($this->client);
		$this->db = $this->m->pled;
		$this->collection = $this->db->vuln_applications;
	}

	function _getCollection() {
		return $this->collection;
	}
}
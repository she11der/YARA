rule SIGNATURE_BASE_Php_Dns : FILE
{
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a52e453b-07aa-58b9-91e7-f2426a8e8976"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L175-L191"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		logic_hash = "650eecc06f215ae6a15078c87d8a8c1597ca9e3d735eacd17b046a9d9deb6aa8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii

	condition:
		filesize <15KB and all of them
}

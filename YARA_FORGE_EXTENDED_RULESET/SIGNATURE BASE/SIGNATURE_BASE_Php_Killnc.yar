rule SIGNATURE_BASE_Php_Killnc : FILE
{
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		author = "Florian Roth (Nextron Systems)"
		id = "241611d3-3636-5a25-b3c3-d45d6cb81c78"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L28-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		logic_hash = "431a9a66f5d0e42856ca5716c2994c018f77cc338300abd71d94ffe7e75da3bf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
		$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
		$s3 = "<?php echo exec('killall nc');?>" fullword ascii
		$s4 = "<title>Laudanum Kill nc</title>" fullword ascii
		$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii

	condition:
		filesize <15KB and 4 of them
}

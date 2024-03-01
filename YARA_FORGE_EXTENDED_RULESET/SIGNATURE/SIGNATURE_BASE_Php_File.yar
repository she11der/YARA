rule SIGNATURE_BASE_Php_File : FILE
{
	meta:
		description = "Laudanum Injector Tools - file file.php"
		author = "Florian Roth (Nextron Systems)"
		id = "68456891-6828-5e42-b8a0-67ecaf83cdc0"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L244-L260"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		logic_hash = "85c14a9c8a6aece231b1cb6dcdd7ed39fdc6aced868c34557ee2e2204ce7007b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$allowedIPs =" fullword ascii
		$s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii
		$s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
		$s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii

	condition:
		filesize <10KB and all of them
}

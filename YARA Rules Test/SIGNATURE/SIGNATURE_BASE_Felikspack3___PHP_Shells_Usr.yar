rule SIGNATURE_BASE_Felikspack3___PHP_Shells_Usr
{
	meta:
		description = "Webshells Auto-generated - file usr.php"
		author = "Florian Roth (Nextron Systems)"
		id = "ab1825fe-96aa-5d97-acd6-eac43a12b237"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8443-L8454"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ade3357520325af50c9098dc8a21a024"
		logic_hash = "f5fd4a4c1b531b23b09505d302dc27d7ba2eb733fcf313c04ba9085b090f7cbe"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"

	condition:
		all of them
}
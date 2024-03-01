rule SIGNATURE_BASE_Webshell_STNC_Webshell_V0_8
{
	meta:
		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
		author = "Florian Roth (Nextron Systems)"
		id = "5dc300a2-9965-52e3-a382-b8d327eb7029"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6312-L6325"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"
		logic_hash = "c2067a1b78c441aa05366b612090e0df895c621843038cc9e65beb6719c0cb9a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
		$s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
		$s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"

	condition:
		2 of them
}

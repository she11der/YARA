rule SIGNATURE_BASE_Shankar_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "0c8ab3eb-574b-5e5a-8117-4efecef94f83"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3669-L3681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"
		logic_hash = "58b365206c18b8394cf1e03b71b8e47be10bc933bc2c05b7b03b7dad94f6d6b8"
		score = 75
		quality = 85
		tags = ""

	strings:
		$sAuthor = "ShAnKaR"
		$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
		$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"

	condition:
		1 of ($s*) and $sAuthor
}

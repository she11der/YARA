rule SIGNATURE_BASE_Webshell_Uploader
{
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		author = "Florian Roth (Nextron Systems)"
		id = "c68e15d9-865e-5269-a91c-00619fe76305"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6027-L6038"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
		logic_hash = "c4b915f60a952131caa2c4f5bb2eea85ef25f27cabb8ad36a6bb928433558954"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword

	condition:
		all of them
}
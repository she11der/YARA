rule SIGNATURE_BASE_Wordpress_Config_Webshell_Preprend___FILE
{
	meta:
		description = "Webshell that uses standard Wordpress wp-config.php file and appends the malicious code in front of it"
		author = "Florian Roth (Nextron Systems)"
		id = "2a432c53-5dee-5a2e-9ccf-9e5d52713af9"
		date = "2017-06-25"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L9734-L9756"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "97d7b85fa191380fe8b26ea60c8735a8f7179acc3a496ff0fc0dc5eefde2fe8a"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = " * @package WordPress" fullword ascii
		$s1 = "define('DB_NAME'," ascii
		$s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
		$fp1 = "iThemes Security Config" ascii

	condition:
		uint32(0)==0x68703f3c and filesize <400KB and $x1 and all of ($s*) and not $x1 in (0..1000) and not 1 of ($fp*)
}
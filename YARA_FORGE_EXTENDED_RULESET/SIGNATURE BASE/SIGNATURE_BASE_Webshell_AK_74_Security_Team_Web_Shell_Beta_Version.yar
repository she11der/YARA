rule SIGNATURE_BASE_Webshell_AK_74_Security_Team_Web_Shell_Beta_Version
{
	meta:
		description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
		author = "Florian Roth (Nextron Systems)"
		id = "e93a6ac3-080f-53d3-8368-b9feb509a2ea"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6251-L6264"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"
		logic_hash = "4fbf8f5cab8593fd88e5a430b849e61d7d663c13700f459aa516c5b337d5438b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
		$s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
		$s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword

	condition:
		1 of them
}

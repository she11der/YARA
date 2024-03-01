rule SIGNATURE_BASE_Felikspack3___PHP_Shells_Phpft
{
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		author = "Florian Roth (Nextron Systems)"
		id = "00bc690b-4977-5076-a40a-edd39c37233f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7689-L7701"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "60ef80175fcc6a879ca57c54226646b1"
		logic_hash = "741536acafdc4da618d69bdae2f0a3e8c004a4027cc76c796158ee111c006414"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "PHP Files Thief"
		$s11 = "http://www.4ngel.net"

	condition:
		all of them
}

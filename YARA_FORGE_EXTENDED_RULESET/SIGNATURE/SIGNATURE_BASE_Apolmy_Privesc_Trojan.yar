rule SIGNATURE_BASE_Apolmy_Privesc_Trojan : FILE
{
	meta:
		description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
		author = "Florian Roth (Nextron Systems)"
		id = "2f3f496b-ebfe-5a6e-89ad-a24af6378fd7"
		date = "2015-08-04"
		modified = "2023-12-05"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_terracotta.yar#L11-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
		logic_hash = "8cce828806d5829735d6ac8d28a48c9b016b96b4370b2f3ac139799a9fe13c4a"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[%d] Failed, %08X" fullword ascii
		$s2 = "[%d] Offset can not fetched." fullword ascii
		$s3 = "PowerShadow2011" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}

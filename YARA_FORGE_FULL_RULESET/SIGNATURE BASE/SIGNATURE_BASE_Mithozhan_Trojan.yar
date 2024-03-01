rule SIGNATURE_BASE_Mithozhan_Trojan : FILE
{
	meta:
		description = "Mitozhan Trojan used in APT Terracotta"
		author = "Florian Roth (Nextron Systems)"
		id = "5e2b4e08-1a35-5eb0-8c25-a73d45b0e279"
		date = "2015-08-04"
		modified = "2023-12-05"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_terracotta.yar#L29-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"
		logic_hash = "a7beb030368cc6e1119617991b68e6fa1bf2d1f6eee28e83fef7862313f19d30"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "adbrowser" fullword wide
		$s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
		$s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}

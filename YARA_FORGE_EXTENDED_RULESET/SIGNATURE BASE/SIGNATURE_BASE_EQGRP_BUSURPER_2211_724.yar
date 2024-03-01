import "pe"

rule SIGNATURE_BASE_EQGRP_BUSURPER_2211_724
{
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d109210e-14df-5b90-a496-fa8a2454126b"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L350-L367"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "834180ef512882cc3b22e79a6bda349678eb5042a3356a50c47eeb36ae453427"
		score = 75
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"

	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "_start_text" ascii
		$s3 = "IMPLANT" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "upgrade_implant" fullword ascii

	condition:
		all of them
}

rule SIGNATURE_BASE_CN_Honker_Nc_MOVE : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file MOVE.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "115d1ec9-6c4f-587e-977c-cd24ada89ab6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L344-L360"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4195370c103ca467cddc8f2724a8e477635be424"
		logic_hash = "49f41162919bb04744041ae6f7438e61d98fb7d5984a17535d9c4ce4d398671b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Destination: http://202.113.20.235/gj/images/2.asp" fullword ascii
		$s1 = "HOST: 202.113.20.235" fullword ascii
		$s2 = "MOVE /gj/images/A.txt HTTP/1.1" fullword ascii

	condition:
		filesize <1KB and all of them
}

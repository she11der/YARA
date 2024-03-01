rule SIGNATURE_BASE_CN_Honker__Builder_Shift_Skinh : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files builder.exe, shift.exe, SkinH.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cb18aa4a-6eba-58ca-a6fc-e4160b90f4d7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2423-L2444"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d15802df98d72b4ef3bac2dfb8ba3338c540ef7290d7ddf9738cf0f7b86e17ea"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "6b5a84cdc3d27c435d49de3f68872d015a5aadfc"
		hash1 = "ee127c1ea1e3b5bf3d2f8754fabf9d1101ed0ee0"
		hash2 = "d593f03ae06e54b653c7850c872c0eed459b301f"

	strings:
		$s1 = "lipboard" fullword ascii
		$s2 = "uxthem" fullword ascii
		$s3 = "ENIGMA" fullword ascii
		$s4 = "UtilW0ndow" fullword ascii
		$s5 = "prog3am" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <6075KB and all of them
}

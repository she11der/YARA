rule SIGNATURE_BASE_CN_Honker_Dedecms5_7 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dedecms5.7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b037862d-2821-5e96-996b-13ab241575ba"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L614-L629"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f9cbb25883828ca266e32ff4faf62f5a9f92c5fb"
		logic_hash = "57ff887906d3c5e7eafc900581eea7432c7a18364b0061d0e4deba0229663c65"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "/data/admin/ver.txt" fullword ascii
		$s2 = "SkinH_EL.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <830KB and all of them
}

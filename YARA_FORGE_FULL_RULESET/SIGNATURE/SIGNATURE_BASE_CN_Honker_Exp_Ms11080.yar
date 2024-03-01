rule SIGNATURE_BASE_CN_Honker_Exp_Ms11080 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "2f5ce2f3-3595-5729-be0c-3f6486cb94fd"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1609-L1624"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
		logic_hash = "57eb1cdd1108c82da399b0aa869edc9e377e0185896504716bec8925599c07f0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s6 = "[*] Add to Administrators success" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <840KB and all of them
}

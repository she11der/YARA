rule SIGNATURE_BASE_CN_Honker_T00Ls_Lpk_Sethc_V3_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v3.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7513a513-e8a3-58a8-8dd5-512ba33ff013"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L685-L701"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fa47c4affbac01ba5606c4862fdb77233c1ef656"
		logic_hash = "fa65de4a135072f4d9a5d5711a4e2833b9d4a268a2a37c33d17e4546d172b6f1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = ":Rices  Forum:T00Ls.Net  [4 Fucker Te@m]" fullword wide
		$s3 = "SkinH_EL.dll" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}

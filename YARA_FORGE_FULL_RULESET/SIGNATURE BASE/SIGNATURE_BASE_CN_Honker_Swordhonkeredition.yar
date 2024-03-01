rule SIGNATURE_BASE_CN_Honker_Swordhonkeredition : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5688fa03-bcb0-545d-9fdf-7ab48a389424"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L559-L575"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3f9479151c2cada04febea45c2edcf5cece1df6c"
		logic_hash = "cc18e68f7c3eff69a75333f3b605c89b024c6763f7b97e0ce20ce14bfe28df0d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\bin\\systemini\\MyPort.ini" wide
		$s1 = "PortThread=200 //" fullword wide
		$s2 = " Port Open -> " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <375KB and all of them
}

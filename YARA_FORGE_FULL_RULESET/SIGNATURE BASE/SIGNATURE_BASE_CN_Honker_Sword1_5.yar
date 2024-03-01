rule SIGNATURE_BASE_CN_Honker_Sword1_5 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Sword1.5.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "832e4998-64fc-5f34-a46d-aeefde0ee763"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L414-L431"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
		logic_hash = "0f7630b2ec983df2a065b049000cef6de38f884254748a342b2fd84d8c5985af"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://www.md5.com.cn" fullword wide
		$s2 = "ListBox_Command" fullword wide
		$s3 = "\\Set.ini" wide
		$s4 = "OpenFileDialog1" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <740KB and all of them
}

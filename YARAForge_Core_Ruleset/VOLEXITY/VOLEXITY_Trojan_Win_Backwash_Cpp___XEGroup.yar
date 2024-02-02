rule VOLEXITY_Trojan_Win_Backwash_Cpp___XEGroup
{
	meta:
		description = "CPP loader for the Backwash malware."
		author = "threatintel@volexity.com"
		id = "8a1c4ff1-1827-5e6f-b838-664d8c3be840"
		date = "2021-11-17"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2021/2021-12-06 - XEGroup/indicators/yara.yar#L3-L20"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "c8ed2d3103aa85363acd7f5573aeb936a5ab5a3bacbcf1f04e6b298299f24dae"
		score = 75
		quality = 80
		tags = ""
		hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "cor1dbg.dll" wide
		$s2 = "XEReverseShell.exe" wide
		$s3 = "XOJUMAN=" wide

	condition:
		2 of them
}
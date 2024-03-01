import "pe"

rule DITEKSHEN_INDICATOR_TOOL_RTK_Hiddenrootkit : FILE
{
	meta:
		description = "Detects the Hidden public rootkit"
		author = "ditekSHen"
		id = "c9e9d160-224f-505f-a135-56a9793f99c2"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L533-L554"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "20180fc040c1b988b17b1ca9b61a7dab5180df4961a00f0afcb03e2cbe99b28f"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$h1 = "Hid_State" fullword wide
		$h2 = "Hid_StealthMode" fullword wide
		$h3 = "Hid_HideFsDirs" fullword wide
		$h4 = "Hid_HideFsFiles" fullword wide
		$h5 = "Hid_HideRegKeys" fullword wide
		$h6 = "Hid_HideRegValues" fullword wide
		$h7 = "Hid_IgnoredImages" fullword wide
		$h8 = "Hid_ProtectedImages" fullword wide
		$s1 = "FLTMGR.SYS" fullword ascii
		$s2 = "HAL.dll" fullword ascii
		$s3 = "\\SystemRoot\\System32\\csrss.exe" fullword wide
		$s4 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\%wZ" fullword wide
		$s5 = "INIT" fullword ascii
		$s6 = "\\hidden-master\\Debug\\QAssist.pdb" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($h*) or 5 of ($s*) or (2 of ($s*) and 2 of ($h*)))
}

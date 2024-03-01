private rule BINARYALERT_Cobaltstrike_Template_Exe_PRIVATE : FILE
{
	meta:
		description = "Template to provide executable detection Cobalt Strike payloads"
		author = "@javutin, @joseselvi"
		id = "39c27acf-1264-584d-99e0-77b0e9352078"
		date = "2017-12-14"
		modified = "2017-12-14"
		reference = "https://www.cobaltstrike.com"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/windows/hacktool_windows_cobaltstrike_template.yara#L1-L28"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "492b2b0b319509fe26473add6ca50c246a0c30fb8a7f9e2631c8d3e9e146c611"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$compiler = "mingw-w64 runtime failure" nocase
		$f1 = "VirtualQuery" fullword
		$f2 = "VirtualProtect" fullword
		$f3 = "vfprintf" fullword
		$f4 = "Sleep" fullword
		$f5 = "GetTickCount" fullword
		$c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and $compiler and all of ($f*) and all of ($c*)
}

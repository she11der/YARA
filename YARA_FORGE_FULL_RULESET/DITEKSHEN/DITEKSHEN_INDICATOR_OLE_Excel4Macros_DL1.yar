rule DITEKSHEN_INDICATOR_OLE_Excel4Macros_DL1 : FILE
{
	meta:
		description = "Detects OLE Excel 4 Macros documents acting as downloaders"
		author = "ditekSHen"
		id = "4212d762-ea49-5884-b697-9313f43140d5"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_office.yar#L740-L764"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a3248027b83b982cccf235267aa27def4f640987d41c5f11509bde3e27b82fee"
		score = 75
		quality = 25
		tags = "FILE"

	strings:
		$s1 = "Macros Excel 4.0" fullword ascii
		$s2 = { 00 4d 61 63 72 6f 31 85 00 }
		$s3 = "http" ascii
		$s4 = "file:" ascii
		$fa_exe = ".exe" ascii nocase
		$fa_scr = ".scr" ascii nocase
		$fa_dll = ".dll" ascii nocase
		$fa_bat = ".bat" ascii nocase
		$fa_cmd = ".cmd" ascii nocase
		$fa_sct = ".sct" ascii nocase
		$fa_txt = ".txt" ascii nocase
		$fa_psw = ".ps1" ascii nocase
		$fa_py = ".py" ascii nocase
		$fa_js = ".js" ascii nocase

	condition:
		uint16(0)==0xcfd0 and (3 of ($s*) and 1 of ($fa*))
}

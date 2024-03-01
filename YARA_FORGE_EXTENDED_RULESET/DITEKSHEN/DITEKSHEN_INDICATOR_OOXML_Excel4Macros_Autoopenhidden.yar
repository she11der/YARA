rule DITEKSHEN_INDICATOR_OOXML_Excel4Macros_Autoopenhidden : FILE
{
	meta:
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet auto_open and state hidden"
		author = "ditekSHen"
		id = "c5aab620-5254-5fc6-b236-4fe0f69cbd8e"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_office.yar#L875-L885"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a93d8aa7ac025a0c2e8a9ac833f6d4c3cd3769ffca3f87455f43411d0021e828"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"

	strings:
		$s1 = "state=\"veryhidden\"" ascii nocase
		$s2 = "<definedName name=\"_xlnm.Auto_Open" ascii nocase

	condition:
		uint32(0)==0x6d783f3c and all of them
}

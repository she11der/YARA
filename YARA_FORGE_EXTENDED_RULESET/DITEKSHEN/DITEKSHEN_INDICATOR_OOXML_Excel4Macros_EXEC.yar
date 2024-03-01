rule DITEKSHEN_INDICATOR_OOXML_Excel4Macros_EXEC : FILE
{
	meta:
		description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet"
		author = "ditekSHen"
		id = "674ef310-d3bc-5e15-862f-29aa111becb3"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_office.yar#L860-L873"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ab3994e4082390f65d030db0b898a20df1d7e4b0ca2fdedc7a9d0f1480fd0334"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"

	strings:
		$ms = "<xm:macrosheet" ascii nocase
		$s1 = ">FORMULA.FILL(" ascii nocase
		$s2 = ">REGISTER(" ascii nocase
		$s3 = ">EXEC(" ascii nocase
		$s4 = ">RUN(" ascii nocase

	condition:
		uint32(0)==0x6d783f3c and $ms and (2 of ($s*) or ($s3))
}

rule DITEKSHEN_INDICATOR_RTF_LNK_Shell_Explorer_Execution : FILE
{
	meta:
		description = "detects RTF files with Shell.Explorer.1 OLE objects with embedded LNK files referencing an executable."
		author = "ditekSHen"
		id = "2cac4dd8-086a-5220-a658-94cedd9cf7c3"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_office.yar#L478-L492"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4c11a37425e260692e11dc8fca317611106245d1590081a7038036ad568702f8"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$clsid = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
		$lnk_header = "4c00000001140200" ascii nocase
		$http_url = "6800740074007000" ascii nocase
		$file_url = "660069006c0065003a" ascii nocase

	condition:
		uint32(0)==0x74725c7b and filesize <1500KB and $clsid and $lnk_header and ($http_url or $file_url)
}

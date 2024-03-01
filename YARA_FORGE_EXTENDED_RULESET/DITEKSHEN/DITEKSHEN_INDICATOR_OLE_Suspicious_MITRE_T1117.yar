rule DITEKSHEN_INDICATOR_OLE_Suspicious_MITRE_T1117 : T1117 FILE
{
	meta:
		description = "Detects MITRE technique T1117 in OLE documents"
		author = "ditekSHen"
		id = "0f41b011-2b63-581f-aa10-9560f27d0a27"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_office.yar#L653-L664"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f0d97f4de8bde18299ee0caee680a15070a1faa99fc318d144a7b7918c8cbb1f"
		score = 65
		quality = 75
		tags = "T1117, FILE"

	strings:
		$s1 = "scrobj.dll" ascii nocase
		$s2 = "regsvr32" ascii nocase
		$s3 = "JyZWdzdnIzMi5leGU" ascii
		$s4 = "HNjcm9iai5kbGw" ascii

	condition:
		uint16(0)==0xcfd0 and 2 of them
}

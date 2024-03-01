rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_PYSA
{
	meta:
		description = "Detects files referencing identities associated with PYSA / Mespinoza ransomware"
		author = "ditekShen"
		id = "b26d472b-c94e-576d-b168-6f273bb8fca5"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L322-L340"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cf0fbc0160f1d21efdb4a6935ae0d2206107042e3d020722f50d2c302aff246c"
		score = 75
		quality = 55
		tags = ""

	strings:
		$s1 = "luebegg8024@onionmail.org" ascii wide nocase
		$s2 = "mayakinggw3732@onionmail.org" ascii wide nocase
		$s3 = "lauriabornhat7722@protonmail.com" ascii wide nocase
		$s4 = "DeborahTrask@onionmail.org" ascii wide nocase
		$s5 = "AlisonRobles@onionmail.org" ascii wide nocase
		$s6 = "NatanSchultz67@protonmail.com" ascii wide nocase
		$s7 = "jonikemppi@onionmail.org" ascii wide nocase
		$s8 = "lanerosalie49003@onionmail.org" ascii wide nocase
		$s9 = "bernalmargaret645@onionmail.org" ascii wide nocase
		$s10 = "carlhubbard2021@protonmail.com" ascii wide nocase
		$u1 = "http://pysa2bitc" ascii wide

	condition:
		any of them
}

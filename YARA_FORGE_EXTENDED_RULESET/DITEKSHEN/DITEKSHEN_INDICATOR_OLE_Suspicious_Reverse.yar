rule DITEKSHEN_INDICATOR_OLE_Suspicious_Reverse : FILE
{
	meta:
		description = "detects OLE documents containing VB scripts with reversed suspicious strings"
		author = "ditekSHen"
		id = "a7f4d18d-add6-5df2-9a8c-f88d8e3766da"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_office.yar#L599-L619"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "04950549eede23b7006103539f20437713a54138c073d9805048392ea0a3df2a"
		score = 65
		quality = 71
		tags = "FILE"

	strings:
		$vb = "\\VBE7.DLL" ascii
		$cmd1 = "CMD C:\\" nocase ascii
		$cmd2 = "CMD /c " nocase ascii
		$kw1 = "]rAHC[" nocase ascii
		$kw2 = "ekOVNI" nocase ascii
		$kw3 = "EcaLPEr" nocase ascii
		$kw4 = "TcEJBO-WEn" nocase ascii
		$kw5 = "eLbAirav-Teg" nocase ascii
		$kw6 = "ReveRSE(" nocase ascii
		$kw7 = "-JOIn" nocase ascii

	condition:
		uint16(0)==0xcfd0 and $vb and ((1 of ($cmd*) and 1 of ($kw*)) or (2 of ($kw*)))
}

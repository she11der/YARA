import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E04A344B397F752A45B128A594A3D6B5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "85a7c3f7-a449-54ad-aac4-53f2a2c6c30e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1637-L1648"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "db3c854b68387aa5c6976783e6f79f99fe3389344b64d38c603d298128193e12"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d73229f3b7c2025a5a56e6e189be8a9120f1b3b0d8a78b7f62eff5c8d2293330"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and pe.signatures[i].serial=="00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5")
}

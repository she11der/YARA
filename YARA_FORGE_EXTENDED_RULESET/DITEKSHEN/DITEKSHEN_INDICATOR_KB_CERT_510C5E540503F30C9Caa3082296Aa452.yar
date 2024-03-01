import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_510C5E540503F30C9Caa3082296Aa452 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "eddbe6f1-fb7c-5129-afb4-6b4d67e39f60"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5033-L5045"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "cb01f31a322572035cf19f6cda00bcf1d8235dcc692588810405d0fc6e8d239c"
		logic_hash = "9b6ad8b3e90fcd63f86b353e89ce7e6226197bfcb491e2151b8dbf580466076e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3e56a13ceb87243b8b2c5de67da54a3a9e0988d7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Systems Analysis 360 Ltd" and pe.signatures[i].serial=="51:0c:5e:54:05:03:f3:0c:9c:aa:30:82:29:6a:a4:52")
}

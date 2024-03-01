import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0084817E07288A5025B9435570E7Fec1D3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "31528b27-4a0c-5e97-b201-07e89248196a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3971-L3982"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "89da849911c6d6a3b6d45166bd9975828887b50ee149dea4cbae9cc5c0ecf6d2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f22e8c59b7769e4a9ade54aee8aaf8404a7feaa7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE6\\x8F\\x90\\xD0\\xAD\\xD0\\xAD\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xD0\\xAD\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\x89\\xBE\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xD0\\xAD\\xE8\\x89\\xBE" and pe.signatures[i].serial=="00:84:81:7e:07:28:8a:50:25:b9:43:55:70:e7:fe:c1:d3")
}

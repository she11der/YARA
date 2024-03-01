import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F097E59809Ae2E771B7B9Ae5Fc3408D7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "edd8674d-7d45-5f77-aa47-3fbe32176324"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2534-L2545"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "817876ab8e649b36cac2e7b23d58fe94963c55481fbf3deff7e60a70896af6d0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "22ad7df275c8b5036ea05b95ce5da768049bd2b21993549eed3a8a5ada990b1e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and pe.signatures[i].serial=="00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7")
}

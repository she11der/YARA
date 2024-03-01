import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0609B5Aad2Dfb81Fbe6B75E4Cfe372A6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "db7bf2e3-f514-5133-a35a-87c43a5f12cf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5073-L5084"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2f483d06fd7af8db8e79203dcd4252d74f4859c0681e0bfcc4a97b351cb758a9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a30013d7a055c98c4bfa097fe85110629ef13e67"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "vVBhgeghjdigSdWYSAdmy" and pe.signatures[i].serial=="06:09:b5:aa:d2:df:b8:1f:be:6b:75:e4:cf:e3:72:a6")
}

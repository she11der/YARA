import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Da173Eb1Ac76340Ac058E1Ff4Bf5E1B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "1ef8f8b6-e4e9-5504-94bd-b24e81de5694"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L681-L692"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c9bfbef4470ee2339ef68484f8a4f21628c0cf9a07770d68d91e6c11e0345786"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "acb38d45108c4f0c8894040646137c95e9bb39d8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALISA LTD" and pe.signatures[i].serial=="5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b")
}

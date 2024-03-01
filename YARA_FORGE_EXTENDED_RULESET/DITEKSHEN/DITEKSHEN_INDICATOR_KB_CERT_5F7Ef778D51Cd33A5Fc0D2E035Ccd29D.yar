import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5F7Ef778D51Cd33A5Fc0D2E035Ccd29D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "95b1cba9-9625-55da-a321-08cdd4d3056f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3633-L3644"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9b57fd9840dceea97a2f013f803e8639add6c6b01f3764b65b3c1fe60ae0dd57"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "87229a298b8de0c7b8d4e23119af1e7850a073f5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ffadbcfabbe" and pe.signatures[i].serial=="5f:7e:f7:78:d5:1c:d3:3a:5f:c0:d2:e0:35:cc:d2:9d")
}

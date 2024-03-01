import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_32Fbf8Cfa43Dca3F85Efabe96Dfefa49 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "9a228e0e-256b-547d-af6d-960089f2f803"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L68-L79"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7e53dcd2e10285f710f1fb2355d77db3507ce346e8d0f26843ca8df2271a6e9e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "498d63bf095195828780dba7b985b71ab08e164f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foxstyle LLC" and pe.signatures[i].serial=="32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49")
}

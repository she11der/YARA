import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Cbc2Af7D82295A8535F3B26B47522640 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d4f422a7-2b1c-5db0-ad9b-1eb8b3a75e3c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3724-L3735"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6d9fb9b36bc4370851fd0f54bb9fb05e02fc7a6288355b57073c31b1feade41e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "08d2c03d0959905b4b04caee1202b8ed748a8bd0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eabfdafffefaccaedaec" and pe.signatures[i].serial=="cb:c2:af:7d:82:29:5a:85:35:f3:b2:6b:47:52:26:40")
}

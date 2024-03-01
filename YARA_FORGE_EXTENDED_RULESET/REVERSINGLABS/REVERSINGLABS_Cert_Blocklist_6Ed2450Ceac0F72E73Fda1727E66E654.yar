import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Ed2450Ceac0F72E73Fda1727E66E654 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c19ddbde-eec0-5ebb-8f11-1e7dcb489bc8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L369-L385"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0e5af7795c825367d441c8abc2aa835fa83083eb8ee1f723c7d2dacff1ca88ff"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hohhot Handing Trade and Business Co., Ltd." and pe.signatures[i].serial=="6e:d2:45:0c:ea:c0:f7:2e:73:fd:a1:72:7e:66:e6:54" and 1376092799<=pe.signatures[i].not_after)
}

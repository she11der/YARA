import "pe"

rule REVERSINGLABS_Cert_Blocklist_760Cef386B63406751Ae83A9Eae92342 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2cbd1fd-ef68-5128-9c45-88b73a49130f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15426-L15442"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "43b56736afe081a1215db67b933413d7fbafbfc1be8213b330668578921ebca7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gidrokon LLC" and pe.signatures[i].serial=="76:0c:ef:38:6b:63:40:67:51:ae:83:a9:ea:e9:23:42" and 1601942400<=pe.signatures[i].not_after)
}

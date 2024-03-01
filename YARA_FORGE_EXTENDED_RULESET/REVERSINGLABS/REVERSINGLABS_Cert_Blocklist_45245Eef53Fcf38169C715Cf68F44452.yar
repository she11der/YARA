import "pe"

rule REVERSINGLABS_Cert_Blocklist_45245Eef53Fcf38169C715Cf68F44452 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "514eac5a-9264-58ef-b4ee-65ec24b43e5a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11310-L11326"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7e0c3147e657802e457f6df271b7f5a64c81fd13f936a8935aa991022e4ab238"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PAPER AND CORE SUPPLIES LTD" and pe.signatures[i].serial=="45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52" and 1639958400<=pe.signatures[i].not_after)
}

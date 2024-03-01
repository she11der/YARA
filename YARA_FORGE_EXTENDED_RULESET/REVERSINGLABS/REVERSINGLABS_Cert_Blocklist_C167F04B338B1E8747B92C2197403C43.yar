import "pe"

rule REVERSINGLABS_Cert_Blocklist_C167F04B338B1E8747B92C2197403C43 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0bf561ac-0283-557f-a685-4603e2b58273"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7690-L7708"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8e0a11efc739baefe23a3d77e4eefc9dc23c74821c91fc219822dbc5dbb468b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and (pe.signatures[i].serial=="00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43" or pe.signatures[i].serial=="c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43") and 1604361600<=pe.signatures[i].not_after)
}

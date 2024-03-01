import "pe"

rule REVERSINGLABS_Cert_Blocklist_F675139Ea68B897A865A98F8E4611F00 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3bac20a3-1415-53af-9d04-a30aa7488dd7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11478-L11496"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2306e90d376f5de8a4eb6d4a696bc1781686d7094cb0a2db48019ee93c1bf60a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BS TEHNIK d.o.o." and (pe.signatures[i].serial=="00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00" or pe.signatures[i].serial=="f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00") and 1606953600<=pe.signatures[i].not_after)
}

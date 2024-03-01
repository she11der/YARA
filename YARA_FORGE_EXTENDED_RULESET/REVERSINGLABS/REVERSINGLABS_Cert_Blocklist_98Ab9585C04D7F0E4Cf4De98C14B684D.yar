import "pe"

rule REVERSINGLABS_Cert_Blocklist_98Ab9585C04D7F0E4Cf4De98C14B684D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "445bb30e-e021-5a75-a47e-29fa567acfa5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12442-L12460"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ba43dd15b13623bb99d88c93fb9e751deb95a546325a1142d9137b25430d07fd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and (pe.signatures[i].serial=="00:98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d" or pe.signatures[i].serial=="98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d") and 1656547200<=pe.signatures[i].not_after)
}

import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ad255D4Ebefa751F3782587396C08629 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e42d2881-efda-5aa0-b455-dabbd3a77e97"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6956-L6974"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "43f44cbedf37094416628c9df23767be3b036519f93222812597777a146ecb24"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ornitek" and (pe.signatures[i].serial=="00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29" or pe.signatures[i].serial=="ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29") and 1614643200<=pe.signatures[i].not_after)
}

import "pe"

rule REVERSINGLABS_Cert_Blocklist_6366A9Ac97Df4De17366943C9B291Aaa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "77d6756b-e948-5771-9ec1-f5159b0e792c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16212-L16228"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dcdfb78d4d779b1cabcdf5b2da1fa27aaa9faaed4d4967630ce45f30304fe227"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "xlgames" and pe.signatures[i].serial=="63:66:a9:ac:97:df:4d:e1:73:66:94:3c:9b:29:1a:aa" and 1326796477<=pe.signatures[i].not_after)
}

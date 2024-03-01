import "pe"

rule SIGNATURE_BASE_APT_CN_APT27_Compromised_Certficate_Jan22_1
{
	meta:
		description = "Detects compromised certifcates used by APT27 malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f2f015af-219d-51ab-9529-01687a879ebb"
		date = "2022-01-29"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt27_hyperbro.yar#L21-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "94a40d55936fc341eaba5e1accc8bfe3a401114298e7a3cc4d5c64af36eadf9e"
		score = 80
		quality = 85
		tags = ""

	condition:
		for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and pe.signatures[i].serial=="08:68:70:51:50:f1:cf:c1:fc:c3:fc:91:a4:49:49:a6")
}

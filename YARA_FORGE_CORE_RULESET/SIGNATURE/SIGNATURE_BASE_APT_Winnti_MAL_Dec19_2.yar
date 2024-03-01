import "pe"

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_2
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "77f2cb7d-90a6-5654-9d2e-6b525cd910a2"
		date = "2019-12-06"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_winnti.yar#L178-L201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "216557999b7100f26556f9f7088b16ba125ac39b308cb77c997d620ce9591d24"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a1 = "IPSecMiniPort" wide fullword
		$a2 = "ndis6fw" wide fullword
		$a3 = "TCPIP" wide fullword
		$a4 = "NDIS.SYS" ascii fullword
		$a5 = "ntoskrnl.exe" ascii fullword
		$a6 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$a7 = "\\Device\\Null" wide
		$a8 = "\\Device" wide
		$a9 = "\\Driver" wide
		$b1 = { 66 81 7? ?? 70 17 }
		$b2 = { 81 7? ?? 07 E0 15 00 }
		$b3 = { 8B 46 18 3D 03 60 15 00 }

	condition:
		(6 of ($a*)) and (2 of ($b*))
}

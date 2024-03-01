import "pe"

rule SIGNATURE_BASE_Turla_APT_Srsvc : TURLA FILE
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		author = "Florian Roth (Nextron Systems)"
		id = "951ee9f8-1ab0-5fd5-be9b-053ec82f6ea2"
		date = "2016-06-09"
		modified = "2023-12-05"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_turla.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "76bd2aacde66114090d1c1767da64728219230964a0bc78a5d830819c46bac3a"
		score = 75
		quality = 85
		tags = "TURLA, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		family = "Turla"
		hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
		hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"

	strings:
		$x1 = "SVCHostServiceDll.dll" fullword ascii
		$s2 = "msimghlp.dll" fullword wide
		$s3 = "srservice" fullword wide
		$s4 = "ModStart" fullword ascii
		$s5 = "ModStop" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and (1 of ($x*) or all of ($s*))) or ( all of them )
}

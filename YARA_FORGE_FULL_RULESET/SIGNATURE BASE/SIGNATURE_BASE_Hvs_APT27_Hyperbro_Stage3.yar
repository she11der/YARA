import "pe"

rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3 : FILE
{
	meta:
		description = "HyperBro Stage 3 detection - also tested in memory"
		author = "Markus Poelloth"
		id = "b4002777-f129-5177-a8f1-690012a207fa"
		date = "2022-02-07"
		modified = "2023-01-07"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt27_hyperbro.yar#L59-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "49c1e70d63d93244b4b44525f2b30c05512b5f3a30d6d7c43c9366a95c84e79b"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"

	strings:
		$s1 = "\\cmd.exe /A" wide
		$s2 = "vftrace.dll" fullword wide
		$s3 = "msmpeng.exe" fullword wide
		$s4 = "\\\\.\\pipe\\testpipe" fullword wide
		$s5 = "thumb.dat" fullword wide
		$g1 = "%s\\%d.exe" fullword wide
		$g2 = "https://%s:%d/api/v2/ajax" fullword wide
		$g3 = " -k networkservice" fullword wide
		$g4 = " -k localservice" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and ((4 of ($s*)) or (4 of ($g*)))
}

import "pe"

rule SIGNATURE_BASE_Cgis4_Cgis4
{
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "98fbf445-b7a5-58fa-8f06-34be7321e2eb"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L347-L362"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
		logic_hash = "2cf3fc6447323cbefe5f5ad02271eeb4c271bb9784d2c29030858542a43fbb04"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"

	condition:
		all of them
}

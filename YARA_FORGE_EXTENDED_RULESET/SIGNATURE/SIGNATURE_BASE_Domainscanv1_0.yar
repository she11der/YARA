import "pe"

rule SIGNATURE_BASE_Domainscanv1_0
{
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "94ead827-8b29-5cb5-82b6-a7ca5087bf7e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L185-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
		logic_hash = "b06d902528fee5d1718d0a2984af3314e92e1ec7033c7596f9fb0e51a20eb848"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"

	condition:
		all of them
}

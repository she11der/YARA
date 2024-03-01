rule SIGNATURE_BASE_APT30_Sample_21 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "72005b40-91f7-5661-9478-8680f999b245"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L559-L575"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d315daa61126616a79a8582145777d8a1565c615"
		logic_hash = "e3e431bb6915d99b8aa1915419b60ba47372005b9b4994a924746a91bad80310"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Service.dll" fullword ascii
		$s1 = "(%s:%s %s)" fullword ascii
		$s2 = "%s \"%s\",%s %s" fullword ascii
		$s5 = "Proxy-%s:%u" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}

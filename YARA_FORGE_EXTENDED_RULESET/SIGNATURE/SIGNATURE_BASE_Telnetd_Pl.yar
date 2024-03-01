rule SIGNATURE_BASE_Telnetd_Pl
{
	meta:
		description = "Semi-Auto-generated  - file telnetd.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "05b5d247-3133-5902-a2ee-b84fa89c7f32"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4768-L4782"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5f61136afd17eb025109304bd8d6d414"
		logic_hash = "faf21758b311fa4c2d11cd60169e6c9a67282cf739b73664456691361a480419"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "0ldW0lf" fullword
		$s1 = "However you are lucky :P"
		$s2 = "I'm FuCKeD"
		$s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
		$s4 = "atrix@irc.brasnet.org"

	condition:
		1 of them
}

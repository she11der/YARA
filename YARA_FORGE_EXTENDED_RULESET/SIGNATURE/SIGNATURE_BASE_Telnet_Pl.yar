rule SIGNATURE_BASE_Telnet_Pl
{
	meta:
		description = "Semi-Auto-generated  - file telnet.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "be4de017-e929-5dd3-a60e-f187456b1a55"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3935-L3946"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dd9dba14383064e219e29396e242c1ec"
		logic_hash = "2d1abc52fc70ce664a19e49e6fa4175bc8d8785dee332d5273323479d9628a8c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "W A R N I N G: Private Server"
		$s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "

	condition:
		all of them
}

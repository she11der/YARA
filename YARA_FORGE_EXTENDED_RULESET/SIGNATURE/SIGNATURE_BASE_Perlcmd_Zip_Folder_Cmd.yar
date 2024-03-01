import "pe"

rule SIGNATURE_BASE_Perlcmd_Zip_Folder_Cmd
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		author = "Florian Roth (Nextron Systems)"
		id = "19e4eca0-bd56-57af-afd2-ee2fc5c7c0df"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2279-L2299"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
		logic_hash = "4391207d66b7ed5ac2db127d3efcf22f8c2bbd0ee1f0c6982d656b91e5e10c8f"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
		$s1 = "s/%20/ /ig;" fullword ascii
		$s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
		$s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
		$s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
		$s6 = "$execthis = $_;" fullword ascii
		$s7 = "system($execthis);" fullword ascii
		$s12 = "s/%2f/\\//ig;" fullword ascii

	condition:
		6 of them
}

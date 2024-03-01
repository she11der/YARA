import "pe"

rule SIGNATURE_BASE_Aspbackdoor_Entice
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "68c61920-9c3c-5bfe-976c-346b258bb406"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2516-L2533"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
		logic_hash = "c11313351565d26d9b16a2d5c3c4589676593fe633c441a1c1a33b3c134a2d56"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
		$s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
		$s4 = "conndb.Execute(sqllanguage)" fullword ascii
		$s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
		$s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii

	condition:
		all of them
}

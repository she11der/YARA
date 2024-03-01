rule SIGNATURE_BASE_SUSP_JAVA_Class_With_VBS_Content : FILE
{
	meta:
		description = "Detects a JAVA class file with strings known from VBS files"
		author = "Florian Roth (Nextron Systems)"
		id = "5c1433e2-e2af-52aa-8a8c-691aaf15760d"
		date = "2019-01-03"
		modified = "2023-12-05"
		reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_suspicious_strings.yar#L250-L267"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5d73392437edd5e974809137c5158c17631e8a7a13464aa4df5f2dd1fd090042"
		score = 60
		quality = 83
		tags = "FILE"
		hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"

	strings:
		$a1 = "java/lang/String" ascii
		$s1 = ".vbs" ascii
		$s2 = "createNewFile" fullword ascii
		$s3 = "wscript" fullword ascii nocase

	condition:
		( uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca) and filesize <100KB and $a1 and 3 of ($s*)
}

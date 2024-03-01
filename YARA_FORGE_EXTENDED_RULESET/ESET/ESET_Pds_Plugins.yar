import "pe"

rule ESET_Pds_Plugins : FILE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "dfa75db5-f21c-5b5e-84ba-3bfdcc3efdcd"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/stantinko/stantinko.yar#L102-L130"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "26bbd380b72fb45206178639d67c8737b9984b140ba1048432949e159946c847"
		score = 75
		quality = 80
		tags = "FILE"
		Author = "Frédéric Vachon"
		Description = "Stantinko PDS' plugins"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "std::_Vector_val<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
		$s2 = "std::_Vector_val<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
		$s3 = "std::vector<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
		$s4 = "std::vector<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
		$s5 = "CHTTPHeaderManager" fullword ascii
		$s6 = "CHTTPPostItemManager *" fullword ascii
		$s7 = "CHTTPHeaderManager *" fullword ascii
		$s8 = "CHTTPPostItemManager" fullword ascii
		$s9 = "CHTTPHeader" fullword ascii
		$s10 = "CHTTPPostItem" fullword ascii
		$s11 = "std::vector<CCookie *,std::allocator<CCookie *> >" fullword ascii
		$s12 = "std::_Vector_val<CCookie *,std::allocator<CCookie *> >" fullword ascii
		$s13 = "CCookieManager *" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (2 of ($s*)))
}

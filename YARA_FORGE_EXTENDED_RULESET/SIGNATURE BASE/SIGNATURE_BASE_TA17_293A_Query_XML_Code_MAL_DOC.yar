import "pe"

rule SIGNATURE_BASE_TA17_293A_Query_XML_Code_MAL_DOC : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "other (modified by Florian Roth)"
		id = "82b0f28a-94b6-52ab-8fd6-cdc05823ac34"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ta17_293A.yar#L108-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fb3a84b66554e6c286ba64046d9b18a819f81108ee965862f288637ccee816d2"
		score = 75
		quality = 85
		tags = "FILE"
		name = "Query_XML_Code_MAL_DOC"

	strings:
		$dir = "word/_rels/" ascii
		$dir2 = "word/theme/theme1.xml" ascii
		$style = "word/styles.xml" ascii

	condition:
		uint32(0)==0x04034b50 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd
}

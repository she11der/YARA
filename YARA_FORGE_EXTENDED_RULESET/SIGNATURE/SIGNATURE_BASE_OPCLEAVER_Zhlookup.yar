rule SIGNATURE_BASE_OPCLEAVER_Zhlookup
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "45ef9a90-db4c-59c3-b694-da3f539b118b"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L287-L300"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9cc476e016708fd1604a63e2391057dc9dd0865448b62742ec596d6de54bf8f6"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "zhLookUp.Properties"

	condition:
		all of them
}

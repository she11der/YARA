rule SIGNATURE_BASE_OPCLEAVER_Synflooder
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "bdaf02f4-1226-569b-9f55-999be7ff397a"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L100-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b5349931c4eb5733f9bf05e7cfac6a434063a01d802665f70384cb29d9ae2a3d"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."

	condition:
		all of them
}

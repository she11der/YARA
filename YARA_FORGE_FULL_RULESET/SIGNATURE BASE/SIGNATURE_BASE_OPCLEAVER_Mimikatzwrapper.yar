rule SIGNATURE_BASE_OPCLEAVER_Mimikatzwrapper
{
	meta:
		description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "e9427e29-e581-5a5b-8f1d-4b9bfeec0946"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L206-L220"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c643e248a9d8dd653ec99f8b59cdc7af945857a6a0321f93cc6983e85f84baba"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "mimikatzWrapper"
		$s2 = "get_mimikatz"

	condition:
		all of them
}
